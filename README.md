Packet Analyser

Overview

Packet Analyser is a Python-based network analysis tool designed to inspect packet capture files and extract useful network information.

Built with Scapy, this project helps cybersecurity students and network defenders understand packet structures, identify protocols, examine IP communication, and analyze basic network traffic patterns.

The project focuses on offline packet analysis for educational and defensive cybersecurity purposes.

Features

* Read PCAP and PCAPNG files
* Identify common network protocols
* Extract source and destination IP addresses
* Analyze TCP flags
* Extract DNS query names
* Summarize protocol statistics
* Identify frequently occurring source and destination IPs
* Export packet details to CSV
* Limit packet analysis for testing purposes

Technologies Used

* Python
* Scapy
* CSV
* Network Protocol Analysis
* PCAP / PCAPNG

Network Protocols

The analyzer supports basic identification of:

* TCP
* UDP
* DNS
* ICMP
* IPv4
* IPv6

Project Structure

packet-Analyser/
│
├── packet_analyzer.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── docs/
│   └── project-notes.md
│
├── examples/
│   └── README.md
│
└── tests/
    └── README.md

Installation

1. Clone the Repository

git clone https://github.com/khojazahersediqi-svg/packet-Analyser.git

2. Navigate to the Project

cd packet-Analyser

3. Create a Virtual Environment

python -m venv .venv

4. Activate the Environment

Windows:

.venv\Scripts\activate

Linux:

source .venv/bin/activate

5. Install Dependencies

pip install -r requirements.txt

Usage

Analyze a packet capture:

python packet_analyzer.py examples/sample_capture.pcap

Analyze a limited number of packets:

python packet_analyzer.py examples/sample_capture.pcap --limit 10

Export packet information to CSV:

python packet_analyzer.py examples/sample_capture.pcap --csv output/packets.csv

Example Analysis

The analyzer can display:

* Total packets analyzed
* Protocol distribution
* Top source IP addresses
* Top destination IP addresses
* DNS queries
* TCP flags
* Packet lengths

Learning Objectives

This project demonstrates practical knowledge of:

* Network protocols and packet structures
* Python programming
* Network traffic analysis
* Defensive cybersecurity
* PCAP file inspection
* Data extraction and reporting
* Basic SOC analysis concepts

Limitations

* The project analyzes packet captures offline.
* It does not decrypt HTTPS or TLS traffic.
* A protocol classification does not automatically indicate malicious activity.
* It is not a replacement for Wireshark or a professional intrusion detection system.

Ethical Use

This project is intended for educational and defensive cybersecurity purposes.

Only analyze network traffic that you own or have explicit authorization to inspect.

Author

Khwaja Zaher Sediqi

GitHub: https://github.com/khojazahersediqi-svg

License

MIT License