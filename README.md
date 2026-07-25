# Packet Analyzer using Python & Scapy

A lightweight network packet analyzer built using **Python** and **Scapy** that captures live network traffic and analyzes common network protocols such as **ARP, IPv4, TCP, UDP, ICMP, and DNS**.

This project was developed as part of a cybersecurity internship to gain practical experience with packet sniffing, protocol analysis, and network programming.

---

## Features

- Capture live network packets
- Analyze IPv4 packets
- Decode TCP packets
  - Source & Destination Ports
  - TCP Flags (SYN, ACK, FIN, RST, PSH, URG)
  - Service Identification
- Decode UDP packets
  - Source & Destination Ports
  - Service Identification
- Analyze ICMP packets
  - ICMP Type
  - ICMP Code
- Analyze DNS packets
  - Query / Response Detection
  - Domain Name
  - DNS Answer
- Analyze ARP packets
  - Request / Reply Detection
  - Sender IP
  - Target IP
- Check for Blaclisted IPs

- Display packet statistics and security report after capture

---

## Supported Protocols

| Protocol | Supported |
|----------|-----------|
| ARP | ✅ |
| IPv4 | ✅ |
| TCP | ✅ |
| UDP | ✅ |
| ICMP | ✅ |
| DNS | ✅ |

---

## Technologies Used

- Python 3
- Scapy
- Linux
- Berkeley Packet Filter (BPF)

---

## Installation

Clone the repository

```bash
git clone https://github.com/AryaXVer7/Packet-analyzer_tool.git

cd packet_analyzer_tool

Create a virtual environment (recommended):

```bash
python3 -m venv .venv
```

Activate it:

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```cmd
.venv\Scripts\activate
```

Install the required package:

```bash
pip install scapy
```
---

## Running the Program

Run the analyzer with root privileges.

```bash
sudo python3 packet_analyzer.py
```

Enter the number of packets to capture when prompted.

Example

```
Enter number of packets you want to capture:
100
```

---

## Sample Output

```
=================================
Source IP      : 192.168.1.10
Destination IP : 8.8.8.8

Flags           : SYN
Service         : HTTPS

Protocol        : TCP
Source Port     : 49152
Destination Port: 443
=================================
```

Example statistics

```
================== Statistics ==================

Total Packets : 100

TCP           : 24
UDP           : 68
ICMP          : 4
ARP           : 4

================================================

================ Security Report ================
Blaclisted IP: 31
=================================================
```

---

## Project Structure

```
packet-analyzer_tool/
│
├── packet_analyzer.py
├── README.md
└── LICENSE
```

---

## Concepts Demonstrated

This project demonstrates practical knowledge of:

- Packet Sniffing
- Network Programming
- TCP/IP Protocol Suite
- ARP Protocol
- DNS Protocol
- TCP Flags
- ICMP Messages
- Protocol Parsing
- Real-time Packet Analysis
- Python Programming
- Scapy

---

## Future Improvements

Potential enhancements include:

- Command-line arguments using `argparse`
- PCAP file analysis
- Export packet details to text or CSV
- Additional protocol support (HTTP, DHCP, FTP, etc.)
- Colored terminal output
- Better DNS record decoding

---

## Learning Outcomes

Through this project, I gained hands-on experience with:

- Capturing live network traffic
- Understanding packet structures
- Parsing multiple network protocols
- Using Scapy for packet analysis
- Building modular Python applications
- Applying networking concepts in practice

---

## License

This project is licensed under the MIT License.

---

## Author

**Aryan**

