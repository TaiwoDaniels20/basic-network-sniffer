from scapy.all import (
    sniff, IP, IPv6, TCP, UDP,
    ICMP, ARP, DNS, Raw, wrpcap
)

from datetime import datetime
from collections import Counter
import argparse


# Store protocol statistics
protocol_stats = Counter()


# Analyze individual captured packets
def analyze_packet(packet, show_payload=False):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 60)
    print("NETWORK PACKET CAPTURED")
    print("=" * 60)

    print(f"Timestamp: {timestamp}")
    print(f"Packet Size: {len(packet)} bytes")

    # IPv4 Analysis
    if IP in packet:

        ip_layer = packet[IP]

        print("IP Version: IPv4")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    # IPv6 Analysis
    elif IPv6 in packet:

        ipv6_layer = packet[IPv6]

        print("IP Version: IPv6")
        print(f"Source IP: {ipv6_layer.src}")
        print(f"Destination IP: {ipv6_layer.dst}")

    # ARP Analysis
    elif ARP in packet:

        arp_layer = packet[ARP]

        print("Protocol: ARP")
        print(f"Source IP: {arp_layer.psrc}")
        print(f"Destination IP: {arp_layer.pdst}")

    # TCP Analysis
    if TCP in packet:

        tcp_layer = packet[TCP]

        print("Protocol: TCP")
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")

        flags = str(tcp_layer.flags)

        flag_names = {
            "S": "SYN",
            "A": "ACK",
            "F": "FIN",
            "R": "RST",
            "P": "PSH",
            "U": "URG",
            "E": "ECE",
            "C": "CWR"
        }

        descriptions = [
            flag_names[flag]
            for flag in flags
            if flag in flag_names
        ]

        print(f"TCP Flags: {flags}")
        print(f"TCP Flag Description: {', '.join(descriptions)}")

    # UDP Analysis
    elif UDP in packet:

        udp_layer = packet[UDP]

        print("Protocol: UDP")
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")

    # ICMP Analysis
    elif ICMP in packet:

        print("Protocol: ICMP")

    # ICMPv6 Analysis
    elif IPv6 in packet and packet[IPv6].nh == 58:

        print("Protocol: ICMPv6")

    # DNS Analysis
    if DNS in packet:

        dns_layer = packet[DNS]

        print("\nDNS INFORMATION")

        if dns_layer.qd:

            query = dns_layer.qd.qname

            if isinstance(query, bytes):
                query = query.decode(errors="replace").rstrip(".")

            print(f"DNS Query: {query}")

    # Payload Analysis
    if Raw in packet:

        payload = bytes(packet[Raw].load)

        print("\nPAYLOAD INFORMATION")
        print(f"Payload Length: {len(payload)} bytes")

        if show_payload:

            preview = payload[:64]

            print("Payload Preview (Hex):")
            print(preview.hex())

    print("=" * 60)


# Calculate protocol statistics
def calculate_statistics(packets):

    stats = Counter()

    for packet in packets:

        stats["Total Packets"] += 1

        if IP in packet:
            stats["IPv4"] += 1

        if IPv6 in packet:
            stats["IPv6"] += 1

        if TCP in packet:
            stats["TCP"] += 1

        if UDP in packet:
            stats["UDP"] += 1

        if ICMP in packet:
            stats["ICMP"] += 1

        if ARP in packet:
            stats["ARP"] += 1

        if DNS in packet:
            stats["DNS"] += 1

        if IPv6 in packet and packet[IPv6].nh == 58:
            stats["ICMPv6"] += 1

    return stats


# Display protocol statistics
def display_statistics(stats):

    print("\n")
    print("=" * 50)
    print("          NETWORK SNIFFER SUMMARY")
    print("=" * 50)

    print(f"\nTotal Packets Captured: {stats['Total Packets']}")

    print("\nPROTOCOL STATISTICS")
    print("-" * 35)

    protocols = [
        "TCP", "UDP", "ICMP", "ICMPv6",
        "ARP", "DNS", "IPv4", "IPv6"
    ]

    for protocol in protocols:

        print(f"{protocol:<12}: {stats[protocol]}")

    print("=" * 50)


# Start packet capturing
def start_sniffer(interface, packet_count, packet_filter,
                  output_file, show_payload):

    print("\nBASIC NETWORK SNIFFER")
    print("-" * 40)

    print(f"Interface: {interface or 'Default'}")
    print(f"Packet Count: {packet_count}")
    print(f"Filter: {packet_filter or 'None'}")
    print(f"Output File: {output_file}")

    print("-" * 40)

    print("\nCapturing network traffic...\n")

    try:

        packets = sniff(
            iface=interface,
            filter=packet_filter,
            prn=lambda packet: analyze_packet(packet, show_payload),
            count=packet_count,
            store=True
        )

        # Calculate statistics
        stats = calculate_statistics(packets)

        # Display summary
        display_statistics(stats)

        # Save captured packets
        if packets:

            wrpcap(output_file, packets)

            print(f"\nPackets successfully saved to: {output_file}")

        else:

            print("\nNo packets captured.")

    except KeyboardInterrupt:

        print("\nPacket capture interrupted.")

    except Exception as error:

        print(f"\nError: {error}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Python Network Sniffer"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor"
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=50,
        help="Number of packets to capture"
    )

    parser.add_argument(
        "-f", "--filter",
        default=None,
        help="BPF capture filter"
    )

    parser.add_argument(
        "-o", "--output",
        default="capture.pcap",
        help="Output PCAP filename"
    )

    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Display limited payload information"
    )

    args = parser.parse_args()

    if args.count <= 0:
        parser.error("Packet count must be greater than zero.")

    start_sniffer(
        args.interface,
        args.count,
        args.filter,
        args.output,
        args.show_payload
    )
