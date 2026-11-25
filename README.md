# Basic Network Sniffer

## Project Overview

The Basic Network Sniffer is a Python-based network traffic monitoring and analysis tool developed using the Scapy library.

The application captures network packets in real time, examines their structures, identifies communication protocols, extracts relevant network information, and saves captured packets for further investigation.

The project demonstrates fundamental concepts of network communication, packet analysis, and protocol identification.

## Objectives

- Capture live network traffic.
- Identify source and destination IP addresses.
- Identify common network protocols.
- Extract source and destination port numbers.
- Analyse TCP flags.
- Examine DNS queries.
- Display packet and payload sizes.
- Calculate protocol statistics.
- Export captured traffic into PCAP files for further analysis.

## Technologies Used

- Python 3
- Scapy
- Kali Linux
- Wireshark
- Network protocols: IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP and DNS.

## Features

### 1. Live Packet Capture
Captures network packets through a specified network interface.

### 2. IP Address Analysis
Identifies source and destination IPv4 and IPv6 addresses.

### 3. Protocol Identification
Recognises TCP, UDP, ICMP, ICMPv6, ARP and DNS traffic.

### 4. TCP Flags Analysis
Identifies TCP control flags, including SYN, ACK, FIN, RST, PSH and URG.

### 5. DNS Analysis
Extracts DNS query names from captured DNS packets.

### 6. Payload Inspection
Displays packet payload sizes and provides an optional limited hexadecimal preview.

### 7. Protocol Statistics
Calculates the number of captured packets belonging to different protocols.

### 8. PCAP Export
Saves captured network traffic into PCAP files for subsequent analysis using Wireshark.

## Installation

Clone or download the project repository.

Navigate into the project directory:

```bash
cd basic-network-sniffer
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the environment:

```bash
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Start packet capturing:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 -c 50
```

Capture TCP traffic:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 -f tcp
```

Capture UDP traffic:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 -f udp
```

Capture ICMP traffic:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 -f icmp
```

Display a limited payload preview:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 --show-payload
```

Specify a PCAP output filename:

```bash
sudo ./venv/bin/python sniffer.py -i eth0 -c 50 -o capture.pcap
```

## Packet Analysis

Captured packets can be examined using Wireshark.

The following display filters can be used:

| Filter | Purpose |
|---|---|
| tcp | Displays TCP packets |
| udp | Displays UDP packets |
| icmp | Displays ICMP packets |
| icmpv6 | Displays ICMPv6 packets |
| arp | Displays ARP packets |
| dns | Displays DNS packets |
| ipv6 | Displays IPv6 packets |
| ip | Displays IPv4 packets |

## Learning Outcomes

Through this project, the following practical skills were developed:

- Understanding network packet structures.
- Analysing IPv4 and IPv6 communication.
- Understanding TCP and UDP transport protocols.
- Observing TCP connection establishment and termination.
- Identifying TCP control flags.
- Analysing DNS queries and responses.
- Capturing and inspecting live network traffic.
- Using Scapy for network programming.
- Using Wireshark for packet-level investigation.
- Understanding packet payloads and encrypted HTTPS communication.

## Limitations

- HTTPS application data is generally encrypted and cannot be interpreted as ordinary plaintext without authorised decryption.
- Packet visibility depends on the network interface and capture environment.
- The application provides basic packet analysis rather than advanced intrusion detection.
- Its protocol identification is limited to the protocols and packet structures implemented in the source code.

## Security and Ethical Considerations

This tool is intended for educational purposes, authorised network monitoring and controlled laboratory exercises.

Only capture traffic on networks and devices for which permission has been granted.

Captured network traffic may contain sensitive information and should be stored securely.

## Author

Developed as a practical cybersecurity internship project.
