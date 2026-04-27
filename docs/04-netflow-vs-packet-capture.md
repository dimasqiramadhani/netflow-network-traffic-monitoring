# 04 — NetFlow vs. Packet Capture

## Comparison Table

| Area                     | NetFlow / IPFIX / sFlow            | Packet Capture (PCAP)                    |
|--------------------------|------------------------------------|------------------------------------------|
| **Data captured**        | Communication metadata             | Full packet content                      |
| **Storage**              | Low — ~50–200 bytes per flow       | Very high — 1 GB/hour at 1 Gbps          |
| **Privacy**              | Lower risk — no payload            | High risk — may contain PII, credentials |
| **Latency**              | Near real-time (flow expiry)       | Real-time with buffering                 |
| **Use case**             | Traffic baseline, anomaly, trend   | Deep forensics, malware analysis         |
| **Scalability**          | High — flows from 10 Gbps feasible | Limited — needs dedicated hardware       |
| **SIEM integration**     | Excellent — fits log format        | Usually requires NDR/PCAP tool           |
| **Payload visibility**   | None                               | Full                                     |
| **Detection limitation** | Cannot see encrypted content       | Can detect within encrypted streams      |
| **Operational use**      | Always-on monitoring               | Triggered capture or sample              |

## When to Use NetFlow vs. PCAP

| Scenario                             | NetFlow | PCAP                    |
|--------------------------------------|---------|-------------------------|
| "Is there unusual outbound traffic?" | Yes     | Could work              |
| "What are our top talkers?"          | Yes     | Overkill                |
| "Is this host beaconing?"            | Yes     | Possible                |
| "What was in the HTTPS transfer?"    | No      | Requires TLS inspection |
| "What malware C2 protocol is this?"  | No      | -                       |
| "Was a password sent in clear text?" | No      | -                       |

## NetFlow + SIEM = Network Behavioral Layer

The SIEM (Wazuh) adds:
- Correlation with endpoint logs (Sysmon, auditd)
- Rule-based alerting on flow patterns
- Dashboard and trend visualization
- Timeline reconstruction during incidents

NetFlow provides the **network behavioral baseline** that endpoint logs lack.
