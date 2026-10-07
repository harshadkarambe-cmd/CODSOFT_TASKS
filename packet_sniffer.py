#!/usr/bin/env python3
"""
CODSOFT Cyber Security Internship - Task 1: Network Packet Sniffer

Captures packets with Scapy, extracts source/destination IP, protocol,
ports, length and payload, and presents them in an organized table.
Optionally saves results to CSV and the raw capture to a .pcap file.

Run with administrator/root privileges.
ETHICAL USE: only capture traffic on networks you own or have
explicit permission to monitor.
"""

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, get_if_list,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
    )
except ImportError:
    sys.exit("Scapy is not installed. Run: pip install scapy")

# Common ports -> application protocol names (for easier reading)
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT",
}

COLUMNS = ["No", "Time", "Source", "Destination", "Protocol",
           "SPort", "DPort", "Len", "Info"]
WIDTHS = [5, 12, 39, 39, 9, 6, 6, 6, 40]

captured_packets = []   # raw packets (for PCAP export)
records = []            # parsed dicts (for CSV export)
proto_counter = Counter()


def payload_preview(raw_bytes, limit=48):
    """Return (hex_string, printable_ascii) for the first `limit` bytes."""
    chunk = raw_bytes[:limit]
    hex_str = chunk.hex(" ")
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return hex_str, ascii_str


def parse_packet(pkt, number):
    """Extract the important fields from a packet into a dictionary."""
    rec = {
        "No": number,
        "Time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "Source": "-", "Destination": "-", "Protocol": "OTHER",
        "SPort": "", "DPort": "", "Len": len(pkt), "Info": "",
        "PayloadHex": "", "PayloadAscii": "",
    }

    # ---- Network layer ----
    if pkt.haslayer(IP):
        rec["Source"], rec["Destination"] = pkt[IP].src, pkt[IP].dst
        rec["Protocol"] = f"IP/{pkt[IP].proto}"
    elif pkt.haslayer(IPv6):
        rec["Source"], rec["Destination"] = pkt[IPv6].src, pkt[IPv6].dst
        rec["Protocol"] = "IPv6"
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec["Source"], rec["Destination"] = arp.psrc, arp.pdst
        rec["Protocol"] = "ARP"
        rec["Info"] = "who-has" if arp.op == 1 else "is-at"

    # ---- Transport / application layer ----
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec["Protocol"] = "TCP"
        rec["SPort"], rec["DPort"] = tcp.sport, tcp.dport
        rec["Info"] = f"Flags={tcp.flags} Seq={tcp.seq}"
        app = WELL_KNOWN_PORTS.get(tcp.dport) or WELL_KNOWN_PORTS.get(tcp.sport)
        if app:
            rec["Protocol"] = f"TCP/{app}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec["Protocol"] = "UDP"
        rec["SPort"], rec["DPort"] = udp.sport, udp.dport
        app = WELL_KNOWN_PORTS.get(udp.dport) or WELL_KNOWN_PORTS.get(udp.sport)
        if app:
            rec["Protocol"] = f"UDP/{app}"
    elif pkt.haslayer(ICMP):
        rec["Protocol"] = "ICMP"
        rec["Info"] = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except AttributeError:
            qname = str(pkt[DNSQR].qname)
        rec["Protocol"] = "DNS"
        rec["Info"] = f"Query: {qname}"

    # ---- Payload ----
    if pkt.haslayer(Raw):
        rec["PayloadHex"], rec["PayloadAscii"] = payload_preview(bytes(pkt[Raw].load))

    return rec


def print_header():
    line = " ".join(f"{c:<{w}}" for c, w in zip(COLUMNS, WIDTHS))
    print(line)
    print("-" * len(line))


def print_row(rec, show_payload):
    cells = [rec[c] for c in COLUMNS]
    print(" ".join(f"{str(v)[:w]:<{w}}" for v, w in zip(cells, WIDTHS)))
    if show_payload and rec["PayloadHex"]:
        print(f"      HEX  : {rec['PayloadHex']}")
        print(f"      ASCII: {rec['PayloadAscii']}")


def build_handler(show_payload):
    def handle(pkt):
        number = len(captured_packets) + 1
        captured_packets.append(pkt)
        rec = parse_packet(pkt, number)
        records.append(rec)
        proto_counter[rec["Protocol"].split("/")[0]] += 1
        print_row(rec, show_payload)
    return handle


def save_csv(path):
    fields = COLUMNS + ["PayloadHex", "PayloadAscii"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    print(f"[+] CSV saved to {path}")


def print_summary():
    print("\n" + "=" * 40)
    print(f" Capture summary: {len(records)} packets")
    print("=" * 40)
    for proto, count in proto_counter.most_common():
        print(f" {proto:<10} {count}")


def main():
    p = argparse.ArgumentParser(description="Simple Scapy packet sniffer")
    p.add_argument("-i", "--iface", help="interface to sniff on (default: auto)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="number of packets to capture (0 = until Ctrl+C)")
    p.add_argument("-t", "--timeout", type=int, default=None,
                   help="stop after N seconds")
    p.add_argument("-f", "--filter", default=None,
                   help="BPF filter, e.g. 'tcp port 80' or 'icmp'")
    p.add_argument("-p", "--payload", action="store_true",
                   help="show hex/ASCII payload preview")
    p.add_argument("--csv", metavar="FILE", help="save parsed packets to CSV")
    p.add_argument("--pcap", metavar="FILE", help="save raw capture to PCAP")
    p.add_argument("--list-ifaces", action="store_true",
                   help="list available interfaces and exit")
    args = p.parse_args()

    if args.list_ifaces:
        print("\n".join(get_if_list()))
        return

    print("[*] Starting capture... press Ctrl+C to stop\n")
    print_header()

    try:
        sniff(iface=args.iface, filter=args.filter, count=args.count,
              timeout=args.timeout, prn=build_handler(args.payload), store=False)
    except PermissionError:
        sys.exit("\n[!] Permission denied. Run as root/administrator (sudo).")
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit(f"\n[!] Capture error: {e}\n    On Windows, install Npcap first.")

    print_summary()
    if args.csv:
        save_csv(args.csv)
    if args.pcap and captured_packets:
        wrpcap(args.pcap, captured_packets)
        print(f"[+] PCAP saved to {args.pcap}")


if __name__ == "__main__":
    main()
