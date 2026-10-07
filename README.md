# CODSOFT Cyber Security Internship - Task 1: Packet Sniffer

A Python network packet analyzer built with Scapy. It captures live traffic and
extracts source IP, destination IP, protocol, ports, packet length, and payload.

> **Ethical use:** Only capture traffic on networks you own or are authorized to monitor.

## Features
- Live capture with optional BPF filters (`tcp port 80`, `icmp`, ...)
- Detects Ethernet/IP/IPv6, ARP, TCP, UDP, ICMP and DNS queries
- Labels common application protocols (HTTP, HTTPS, SSH, DNS, ...)
- Hex + ASCII payload preview
- Protocol summary at the end
- Export to CSV and PCAP (open the PCAP in Wireshark)

## Setup
```bash
pip install scapy
```
- **Linux/macOS:** run with `sudo`
- **Windows:** install [Npcap](https://npcap.com) and run the terminal as Administrator

## Usage
```bash
sudo python3 packet_sniffer.py --list-ifaces
sudo python3 packet_sniffer.py -c 50
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80" -p
sudo python3 packet_sniffer.py -t 30 --csv out.csv --pcap out.pcap
```

| Option | Description |
|---|---|
| `-i` | Interface to sniff on |
| `-c` | Packet count (0 = until Ctrl+C) |
| `-t` | Timeout in seconds |
| `-f` | BPF filter |
| `-p` | Show payload preview |
| `--csv` / `--pcap` | Save output |

## Sample output
```
No    Time         Source     Destination  Protocol  SPort DPort Len   Info
1     14:02:11.123 192.168.1.5 142.250.x.x  TCP/HTTPS 51734 443   66    Flags=S Seq=...
2     14:02:11.140 192.168.1.5 8.8.8.8      DNS       58211 53    74    Query: example.com
```

## How it works
Scapy's `sniff()` passes each packet to a handler that walks the protocol layers
(IP -> TCP/UDP/ICMP -> DNS/Raw), pulls out the fields above, and prints a table row.
