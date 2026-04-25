# 03 — NetFlow Concept

## What Is a Network Flow?

A **flow** is a sequence of packets sharing the same characteristics over a time period:
- Same source IP and destination IP
- Same source port and destination port
- Same protocol (TCP/UDP/ICMP)
- Same Type of Service (ToS)

When this 5-tuple (src IP, dst IP, src port, dst port, protocol) conversation ends — by TCP FIN/RST, timeout, or flow expiry — the exporter sends a **flow record** to the collector.

## Common Flow Fields

| Field | Description | Detection Value |
|-------|-------------|----------------|
| `start_time` | Flow start timestamp | Timeline analysis |
| `end_time` | Flow end timestamp | Duration calculation |
| `duration` | Flow duration in seconds | Long sessions, beaconing |
| `protocol` | TCP/UDP/ICMP | Unusual protocol usage |
| `src_ip` | Source IP address | Source attribution |
| `src_port` | Source port | Ephemeral vs. unusual |
| `dst_ip` | Destination IP address | External/internal |
| `dst_port` | Destination port | Service identification |
| `bytes` | Total bytes in flow | Exfiltration detection |
| `packets` | Total packets | DoS, scanning patterns |
| `tcp_flags` | SYN/ACK/FIN/RST flags | Scan detection |
| `in_iface` | Input interface | Traffic source direction |
| `out_iface` | Output interface | Traffic egress direction |

## NetFlow Versions

| Version | Notes |
|---------|-------|
| NetFlow v5 | Original Cisco format — fixed fields, IPv4 only |
| NetFlow v9 | Template-based, flexible fields, supports IPv6 |
| IPFIX (v10) | IETF standard based on NetFlow v9, preferred for modern deployments |
| sFlow | Packet sampling (not true flow) — different from NetFlow |

## Why NetFlow Is Not Packet Capture

NetFlow provides **metadata about communications**, not the communications themselves:

```
Packet Capture (PCAP):
[TCP Header][IP Header][HTTP Header: GET /secret-docs/budget.xlsx HTTP/1.1][Payload: confidential data...]

NetFlow Record:
src=192.168.56.10  dst=203.0.113.50  sport=54321  dport=80  bytes=1482309  duration=45.2s
```

The NetFlow record tells you *a large transfer happened to that IP on port 80*. The PCAP tells you *exactly what was transferred*. Both are useful — for different purposes.
