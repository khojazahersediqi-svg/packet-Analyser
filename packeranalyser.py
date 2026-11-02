#!/usr/bin/env python3
"""
packet_analyzer.py

A dependency-free (standard library only) network packet analyzer for
blue-team triage. It reads classic .pcap captures (or captures live on
Linux), decodes the common protocol layers by hand with `struct`, builds
traffic statistics, and runs explainable detections over the result.

Decoded layers:
    Ethernet (incl. one 802.1Q VLAN tag) -> ARP | IPv4 | IPv6
    IPv4/IPv6 -> TCP | UDP | ICMP/ICMPv6
    UDP/53    -> DNS question names

Detections (every finding states exactly what was observed):
    - TCP port scan         one source probing many ports on one host
    - Host sweep            one source probing the same port on many hosts
    - SYN flood indicator   very many bare SYNs aimed at one host
    - ICMP sweep            one source pinging many hosts
    - ARP spoofing hint     one IP address claimed by multiple MAC addresses
    - Suspicious DNS names  very long or high-entropy names (DGA / tunneling hint)
    - Cleartext protocols   Telnet, FTP, HTTP, POP3, IMAP traffic observed

This is a passive analysis tool: it only reads packets. It does not
inject, modify, or replay traffic, and it does not extract credentials
or payload contents -- it reports that cleartext protocols are in use,
not what was said over them.

Usage:
    python3 packet_analyzer.py analyze capture.pcap
    python3 packet_analyzer.py analyze capture.pcap --json report.json
    sudo python3 packet_analyzer.py capture --count 200 --write out.pcap
"""

from __future__ import annotations

import argparse
import json
import math
import socket
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator


# ======================================================================
# Constants
# ======================================================================

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),   # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
ICMP_ECHO_REQUEST = 8
ICMPV6_ECHO_REQUEST = 128
ARP_REQUEST, ARP_REPLY = 1, 2

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
}
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}

# Detection thresholds
PORT_SCAN_MIN_PORTS = 15
HOST_SWEEP_MIN_HOSTS = 15
SYN_FLOOD_MIN_SYNS = 100
ICMP_SWEEP_MIN_HOSTS = 10
DNS_MAX_NORMAL_NAME_LENGTH = 60
DNS_MAX_NORMAL_LABEL_LENGTH = 35
DNS_HIGH_ENTROPY = 3.8
DNS_ENTROPY_MIN_LENGTH = 14


# ======================================================================
# Data model
# ======================================================================

class Severity(str, Enum):
    INFO = "Info"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    title: str
    detail: str


@dataclass
class Packet:
    """A decoded packet. Fields a layer does not provide stay None."""
    timestamp: float
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    l3: str = "Other"            # IPv4 | IPv6 | ARP | Other
    src_ip: str | None = None
    dst_ip: str | None = None
    l4: str = ""                 # TCP | UDP | ICMP | ICMPv6 | ""
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    dns_query: str | None = None
    arp_op: int | None = None
    arp_mac: str | None = None   # sender hardware address claimed in ARP

    @property
    def is_bare_syn(self) -> bool:
        return (
            self.tcp_flags is not None
            and bool(self.tcp_flags & TCP_SYN)
            and not self.tcp_flags & TCP_ACK
        )

    @property
    def service(self) -> str:
        for port in (self.dst_port, self.src_port):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
        return ""


# ======================================================================
# Protocol decoding
# ======================================================================

def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_dns_question(payload: bytes) -> str | None:
    """Returns the first question name of a DNS message, or None."""
    if len(payload) < 13:
        return None
    question_count = struct.unpack_from("!H", payload, 4)[0]
    if question_count < 1:
        return None

    labels: list[str] = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            return ".".join(labels) if labels else None
        if length & 0xC0:          # compression pointer: not expected in a question
            return None
        offset += 1
        label = payload[offset:offset + length]
        if len(label) < length:
            return None
        labels.append(label.decode("ascii", errors="replace"))
        offset += length
    return None


def _parse_transport(packet: Packet, protocol: int, payload: bytes) -> None:
    if protocol == PROTO_TCP and len(payload) >= 20:
        packet.l4 = "TCP"
        packet.src_port, packet.dst_port = struct.unpack_from("!HH", payload, 0)
        packet.tcp_flags = payload[13]
    elif protocol == PROTO_UDP and len(payload) >= 8:
        packet.l4 = "UDP"
        packet.src_port, packet.dst_port = struct.unpack_from("!HH", payload, 0)
        if 53 in (packet.src_port, packet.dst_port):
            packet.dns_query = _parse_dns_question(payload[8:])
    elif protocol in (PROTO_ICMP, PROTO_ICMPV6) and len(payload) >= 2:
        packet.l4 = "ICMP" if protocol == PROTO_ICMP else "ICMPv6"
        packet.icmp_type = payload[0]


def _parse_ipv4(packet: Packet, data: bytes) -> None:
    if len(data) < 20:
        return
    header_length = (data[0] & 0x0F) * 4
    total_length = struct.unpack_from("!H", data, 2)[0]
    protocol = data[9]
    packet.l3 = "IPv4"
    packet.src_ip = socket.inet_ntop(socket.AF_INET, data[12:16])
    packet.dst_ip = socket.inet_ntop(socket.AF_INET, data[16:20])
    end = total_length if 0 < total_length <= len(data) else len(data)
    _parse_transport(packet, protocol, data[header_length:end])


def _parse_ipv6(packet: Packet, data: bytes) -> None:
    if len(data) < 40:
        return
    packet.l3 = "IPv6"
    next_header = data[6]
    packet.src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    packet.dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    _parse_transport(packet, next_header, data[40:])   # extension headers not followed


def _parse_arp(packet: Packet, data: bytes) -> None:
    if len(data) < 28:
        return
    packet.l3 = "ARP"
    packet.arp_op = struct.unpack_from("!H", data, 6)[0]
    packet.arp_mac = _format_mac(data[8:14])
    packet.src_ip = socket.inet_ntop(socket.AF_INET, data[14:18])
    packet.dst_ip = socket.inet_ntop(socket.AF_INET, data[24:28])


def decode_ethernet_frame(timestamp: float, frame: bytes) -> Packet | None:
    """Decodes one Ethernet frame; returns None if too short to be valid."""
    if len(frame) < 14:
        return None

    packet = Packet(
        timestamp=timestamp,
        length=len(frame),
        dst_mac=_format_mac(frame[0:6]),
        src_mac=_format_mac(frame[6:12]),
    )
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    if ethertype == ETHERTYPE_VLAN and len(frame) >= 18:
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        offset = 18

    body = frame[offset:]
    if ethertype == ETHERTYPE_IPV4:
        _parse_ipv4(packet, body)
    elif ethertype == ETHERTYPE_IPV6:
        _parse_ipv6(packet, body)
    elif ethertype == ETHERTYPE_ARP:
        _parse_arp(packet, body)
    return packet


# ======================================================================
# Capture sources and sinks
# ======================================================================

class PcapFormatError(Exception):
    """Raised when a file is not a readable classic pcap capture."""


def read_pcap(path: Path) -> Iterator[Packet]:
    """Yields decoded packets from a classic libpcap file."""
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic == PCAPNG_MAGIC:
            raise PcapFormatError(
                "pcapng files are not supported; convert with: editcap -F pcap in.pcapng out.pcap"
            )
        if magic not in PCAP_MAGICS:
            raise PcapFormatError("not a recognized pcap file (bad magic number)")

        endian, ticks_per_second = PCAP_MAGICS[magic]
        header_rest = handle.read(20)
        if len(header_rest) < 20:
            raise PcapFormatError("truncated pcap global header")
        link_type = struct.unpack(f"{endian}IIIII", header_rest)[4]
        if link_type != LINKTYPE_ETHERNET:
            raise PcapFormatError(f"unsupported link type {link_type} (only Ethernet is supported)")

        yield from _read_pcap_records(handle, endian, ticks_per_second)


def _read_pcap_records(handle: BinaryIO, endian: str, ticks_per_second: int) -> Iterator[Packet]:
    record_header = struct.Struct(f"{endian}IIII")
    while True:
        raw_header = handle.read(record_header.size)
        if len(raw_header) < record_header.size:
            return
        seconds, fraction, captured_length, _ = record_header.unpack(raw_header)
        frame = handle.read(captured_length)
        if len(frame) < captured_length:
            return  # truncated final record
        packet = decode_ethernet_frame(seconds + fraction / ticks_per_second, frame)
        if packet is not None:
            yield packet


class PcapWriter:
    """Writes captured frames to a classic little-endian pcap file."""

    def __init__(self, path: Path) -> None:
        self._handle = path.open("wb")
        self._handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

    def write(self, timestamp: float, frame: bytes) -> None:
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        self._handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        self._handle.write(frame)

    def close(self) -> None:
        self._handle.close()


def capture_live(
    max_packets: int, duration: float, interface: str | None
) -> Iterator[tuple[float, bytes]]:
    """Yields (timestamp, raw_frame) from a Linux AF_PACKET raw socket.
    Requires root (CAP_NET_RAW)."""
    if not hasattr(socket, "AF_PACKET"):
        raise OSError("live capture requires Linux (AF_PACKET sockets)")

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    try:
        if interface:
            sniffer.bind((interface, 0))
        sniffer.settimeout(1.0)
        deadline = time.time() + duration
        captured = 0
        while captured < max_packets and time.time() < deadline:
            try:
                frame, _ = sniffer.recvfrom(65535)
            except socket.timeout:
                continue
            captured += 1
            yield time.time(), frame
    finally:
        sniffer.close()


# ======================================================================
# Statistics
# ======================================================================

@dataclass
class TrafficStats:
    packet_count: int = 0
    byte_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    protocols: Counter = field(default_factory=Counter)
    services: Counter = field(default_factory=Counter)
    bytes_by_source: Counter = field(default_factory=Counter)
    packets_by_destination_port: Counter = field(default_factory=Counter)

    def add(self, packet: Packet) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        if self.first_timestamp is None:
            self.first_timestamp = packet.timestamp
        self.last_timestamp = packet.timestamp

        self.protocols[packet.l4 or packet.l3] += 1
        # Bare SYNs are connection attempts (often scan/flood noise), not
        # evidence that a service was actually spoken, so they are skipped.
        if packet.service and not packet.is_bare_syn:
            self.services[packet.service] += 1
        if packet.src_ip:
            self.bytes_by_source[packet.src_ip] += packet.length
        if packet.dst_port is not None:
            self.packets_by_destination_port[packet.dst_port] += 1

    @property
    def duration_seconds(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return round(self.last_timestamp - self.first_timestamp, 3)

    def to_dict(self) -> dict:
        return {
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "duration_seconds": self.duration_seconds,
            "protocols": dict(self.protocols.most_common()),
            "services": dict(self.services.most_common()),
            "top_talkers_by_bytes": dict(self.bytes_by_source.most_common(10)),
            "top_destination_ports": {
                str(port): count for port, count in self.packets_by_destination_port.most_common(10)
            },
        }


# ======================================================================
# Detections
# ======================================================================

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())


def detect_port_scans_and_sweeps(packets: Iterable[Packet]) -> list[Finding]:
    ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    hosts_by_source_port: dict[tuple[str, int], set[str]] = defaultdict(set)

    for p in packets:
        if p.is_bare_syn and p.src_ip and p.dst_ip and p.dst_port is not None:
            ports_by_pair[(p.src_ip, p.dst_ip)].add(p.dst_port)
            hosts_by_source_port[(p.src_ip, p.dst_port)].add(p.dst_ip)

    findings = []
    for (src, dst), ports in ports_by_pair.items():
        if len(ports) >= PORT_SCAN_MIN_PORTS:
            findings.append(Finding(
                Severity.HIGH, "TCP port scan",
                f"{src} sent SYNs to {len(ports)} distinct ports on {dst}.",
            ))
    for (src, port), hosts in hosts_by_source_port.items():
        if len(hosts) >= HOST_SWEEP_MIN_HOSTS:
            findings.append(Finding(
                Severity.MEDIUM, "Host sweep",
                f"{src} probed TCP port {port} on {len(hosts)} different hosts.",
            ))
    return findings


def detect_syn_flood(packets: Iterable[Packet]) -> list[Finding]:
    syns_by_target: Counter = Counter(
        p.dst_ip for p in packets if p.is_bare_syn and p.dst_ip
    )
    return [
        Finding(Severity.HIGH, "SYN flood indicator",
                f"{target} received {count} bare SYN packets in this capture.")
        for target, count in syns_by_target.items() if count >= SYN_FLOOD_MIN_SYNS
    ]


def detect_icmp_sweeps(packets: Iterable[Packet]) -> list[Finding]:
    echo_types = {ICMP_ECHO_REQUEST, ICMPV6_ECHO_REQUEST}
    targets_by_source: dict[str, set[str]] = defaultdict(set)
    for p in packets:
        if p.l4 in ("ICMP", "ICMPv6") and p.icmp_type in echo_types and p.src_ip and p.dst_ip:
            targets_by_source[p.src_ip].add(p.dst_ip)

    return [
        Finding(Severity.MEDIUM, "ICMP sweep",
                f"{src} sent echo requests to {len(targets)} different hosts.")
        for src, targets in targets_by_source.items() if len(targets) >= ICMP_SWEEP_MIN_HOSTS
    ]


def detect_arp_spoofing(packets: Iterable[Packet]) -> list[Finding]:
    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    for p in packets:
        if p.l3 == "ARP" and p.src_ip and p.arp_mac and p.src_ip != "0.0.0.0":
            macs_by_ip[p.src_ip].add(p.arp_mac)

    return [
        Finding(Severity.HIGH, "Possible ARP spoofing",
                f"IP {ip} was claimed by {len(macs)} different MAC addresses: {', '.join(sorted(macs))}.")
        for ip, macs in macs_by_ip.items() if len(macs) > 1
    ]


def detect_suspicious_dns(packets: Iterable[Packet]) -> list[Finding]:
    suspicious_by_source: dict[str, list[str]] = defaultdict(list)
    for p in packets:
        name = p.dns_query
        if not name or not p.src_ip:
            continue
        labels = name.split(".")
        first_label = labels[0]
        too_long = len(name) > DNS_MAX_NORMAL_NAME_LENGTH or max(map(len, labels)) > DNS_MAX_NORMAL_LABEL_LENGTH
        random_looking = (
            len(first_label) >= DNS_ENTROPY_MIN_LENGTH
            and _shannon_entropy(first_label) >= DNS_HIGH_ENTROPY
        )
        if too_long or random_looking:
            suspicious_by_source[p.src_ip].append(name)

    return [
        Finding(Severity.MEDIUM, "Suspicious DNS query names",
                f"{src} queried {len(names)} unusually long or random-looking name(s), e.g. '{names[0]}'. "
                f"Can indicate DGA malware or DNS tunneling.")
        for src, names in suspicious_by_source.items()
    ]


def detect_cleartext_protocols(packets: Iterable[Packet]) -> list[Finding]:
    counts: Counter = Counter(
        CLEARTEXT_PORTS[p.dst_port] for p in packets
        if p.l4 == "TCP" and p.dst_port in CLEARTEXT_PORTS and not p.is_bare_syn
    )
    return [
        Finding(Severity.INFO, "Cleartext protocol in use",
                f"{count} {protocol} packet(s) observed; traffic on this protocol is unencrypted.")
        for protocol, count in counts.items()
    ]


DETECTORS = (
    detect_port_scans_and_sweeps,
    detect_syn_flood,
    detect_icmp_sweeps,
    detect_arp_spoofing,
    detect_suspicious_dns,
    detect_cleartext_protocols,
)

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.INFO: 2}


def run_detections(packets: list[Packet]) -> list[Finding]:
    findings = [finding for detector in DETECTORS for finding in detector(packets)]
    return sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])


# ======================================================================
# Reporting and CLI
# ======================================================================

def analyze_packets(packets: list[Packet]) -> tuple[TrafficStats, list[Finding]]:
    stats = TrafficStats()
    for packet in packets:
        stats.add(packet)
    return stats, run_detections(packets)


def print_report(source: str, stats: TrafficStats, findings: list[Finding]) -> None:
    print("=" * 70)
    print(f" PACKET ANALYSIS — {source}")
    print("=" * 70)
    print(f"Packets : {stats.packet_count:,}    Bytes: {stats.byte_count:,}    "
          f"Duration: {stats.duration_seconds}s")

    print("\nProtocols:")
    for name, count in stats.protocols.most_common():
        print(f"  {name or 'Other':<8} {count:>8,}")

    if stats.services:
        print("\nServices:")
        for name, count in stats.services.most_common(8):
            print(f"  {name:<10} {count:>8,}")

    if stats.bytes_by_source:
        print("\nTop talkers (by bytes sent):")
        for ip, size in stats.bytes_by_source.most_common(5):
            print(f"  {ip:<40} {size:>10,}")

    print("\n" + "-" * 70)
    print("FINDINGS")
    print("-" * 70)
    if not findings:
        print("  No suspicious patterns detected by the built-in heuristics.")
    for finding in findings:
        print(f"  [{finding.severity.value.upper():<6}] {finding.title}: {finding.detail}")
    print("=" * 70)


def _write_json_report(path: Path, source: str, stats: TrafficStats, findings: list[Finding]) -> None:
    report = {
        "source": source,
        "stats": stats.to_dict(),
        "findings": [
            {"severity": f.severity.value, "title": f.title, "detail": f.detail} for f in findings
        ],
    }
    path.write_text(json.dumps(report, indent=2))
    print(f"\nFull JSON report written to {path}")


def _run_analyze(args: argparse.Namespace) -> None:
    packets = list(read_pcap(Path(args.pcap_file)))
    stats, findings = analyze_packets(packets)
    print_report(args.pcap_file, stats, findings)
    if args.json:
        _write_json_report(Path(args.json), args.pcap_file, stats, findings)


def _run_capture(args: argparse.Namespace) -> None:
    writer = PcapWriter(Path(args.write)) if args.write else None
    packets: list[Packet] = []
    try:
        for timestamp, frame in capture_live(args.count, args.duration, args.interface):
            if writer:
                writer.write(timestamp, frame)
            packet = decode_ethernet_frame(timestamp, frame)
            if packet:
                packets.append(packet)
    finally:
        if writer:
            writer.close()

    stats, findings = analyze_packets(packets)
    print_report("live capture", stats, findings)
    if args.json:
        _write_json_report(Path(args.json), "live capture", stats, findings)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive network packet analyzer.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a classic .pcap file.")
    analyze.add_argument("pcap_file")
    analyze.add_argument("--json", metavar="OUTPUT_PATH", help="Write the report as JSON.")
    analyze.set_defaults(handler=_run_analyze)

    capture = subparsers.add_parser("capture", help="Capture live traffic (Linux, needs root).")
    capture.add_argument("--count", type=int, default=100, help="Max packets to capture.")
    capture.add_argument("--duration", type=float, default=30.0, help="Max seconds to capture.")
    capture.add_argument("--interface", help="Interface name, e.g. eth0 (default: all).")
    capture.add_argument("--write", metavar="PCAP_PATH", help="Also save the capture to a pcap file.")
    capture.add_argument("--json", metavar="OUTPUT_PATH", help="Write the report as JSON.")
    capture.set_defaults(handler=_run_capture)

    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()
    try:
        args.handler(args)
    except (FileNotFoundError, PcapFormatError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Error: live capture needs root privileges (try sudo).", file=sys.stderr)
        sys.exit(1)
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
