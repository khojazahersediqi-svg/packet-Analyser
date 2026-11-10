Packet Analyser — System Architecture

1. Overview

Packet Analyser follows a modular packet-processing architecture. It uses Python and Scapy to read offline network captures, extract packet information, classify protocols, and generate analytical reports.

2. Architecture Diagram

        PCAP / PCAPNG File
                 |
                 v
        Packet File Reader
              (Scapy)
                 |
                 v
          Packet Processing
                 |
          +------+------+
          |             |
          v             v
    Protocol         IP Address
    Detection        Extraction
          |             |
          v             v
     TCP Flags       Source / Destination
     Extraction      IP Information
          |
          v
     DNS Query Extraction
          |
          v
      Data Aggregation
       (Python Counters)
          |
          v
      Analysis Report
          |
       +--+--+
       |     |
       v     v
    Terminal  CSV Export
       |     |
       +--+--+
          |
          v
       Final Output

3. Main Components

3.1 Packet Input Layer

Responsible for reading packet capture files.

Supported formats:

* PCAP
* PCAPNG

Technology: Scapy rdpcap().

3.2 Packet Processing Layer

Processes individual packets and extracts relevant information.

Tasks:

* Identify packet protocols.
* Extract source and destination IP addresses.
* Read TCP flags.
* Extract DNS query names.
* Calculate packet lengths.

3.3 Protocol Detection Module

Classifies packets into supported protocol categories:

* TCP
* UDP
* DNS
* ICMP
* IPv4
* IPv6
* Other

3.4 Data Analysis Layer

Uses Python data structures such as:

* Lists
* Dictionaries
* Counters

It calculates:

* Total packet count.
* Protocol distribution.
* Most frequent source IP addresses.
* Most frequent destination IP addresses.
* DNS query statistics.

3.5 Reporting Layer

Presents the analysis results through:

* Terminal output.
* CSV report files.

4. Processing Workflow

1. User provides a packet capture file.
2. Scapy reads the capture.
3. The analyzer processes packets individually.
4. Protocols and network fields are identified.
5. Extracted information is stored.
6. Statistical summaries are generated.
7. Results are displayed or exported to CSV.

5. Technology Stack

Component	Technology
Programming language	Python
Packet analysis	Scapy
Packet format	PCAP / PCAPNG
Data processing	Python Collections
Report generation	CSV
Version control	Git / GitHub

6. Security Considerations

* Analyze only authorized packet captures.
* Protect captured network information.
* Avoid uploading sensitive PCAP files publicly.
* Do not treat protocol identification as proof of an attack.
* Encrypted traffic is not decrypted by this tool.

7. Future Architecture Improvements

* Protocol-specific filtering.
* Advanced TCP session analysis.
* HTTP metadata inspection where visible.
* DNS anomaly detection.
* Suspicious traffic indicators.
* JSON reporting.
* Graphical analysis dashboard.
* Authorized live packet capture.

8. Project Goal

The goal is to develop a practical Python-based packet analysis tool that demonstrates fundamental networking, programming, and defensive cybersecurity concepts.