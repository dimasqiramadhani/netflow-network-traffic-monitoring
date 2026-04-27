# 12 — Detection Use Cases

## 1. Port Scanning (T1046)

**What it looks like in flows:**
```
src=192.168.56.10  dst=192.168.56.20  dport=22   bytes=60   packets=1   flags=SYN   (no response)
src=192.168.56.10  dst=192.168.56.20  dport=23   bytes=60   packets=1   flags=SYN   (no response)
src=192.168.56.10  dst=192.168.56.20  dport=80   bytes=60   packets=1   flags=SYN   (response)
... (20+ different ports in 30 seconds)
```

**Detection logic:** One source IP contacts many distinct destination ports in a short timeframe. Flows are tiny (just SYN). TCP flags show mostly SYN without corresponding FIN/ACK.

**False positive sources:** Vulnerability scanners (authorized), network inventory tools, health checks.

---

## 2. High Outbound Traffic / Possible Exfiltration (T1041, T1567)

**What it looks like in flows:**
```
src=192.168.56.10  dst=203.0.113.50  dport=443  bytes=52428800  duration=3600s
(52 MB upload over HTTPS to external IP)
```

**Detection logic:** Outbound bytes exceed threshold from a single source. Long-duration flows to external destinations. Compare against normal baseline for that host.

**False positive sources:** Backup jobs, cloud sync, software updates, video conferencing.

---

## 3. Beaconing (T1071)

**What it looks like in flows:**
```
T+0:   src=192.168.56.30  dst=203.0.113.99  dport=80  bytes=512  duration=1s
T+300: src=192.168.56.30  dst=203.0.113.99  dport=80  bytes=519  duration=1s
T+600: src=192.168.56.30  dst=203.0.113.99  dport=80  bytes=508  duration=1s
(Every 5 minutes, same source, same destination, similar bytes)
```

**Detection logic:** Repeated connections to the same destination with consistent timing interval and similar byte counts — characteristic of C2 check-in behavior.

---

## 4. Lateral Movement (T1021)

**What it looks like in flows:**
```
src=192.168.56.10  dst=192.168.56.20  dport=445  bytes=4096   (SMB)
src=192.168.56.10  dst=192.168.56.30  dport=445  bytes=4096   (SMB)
src=192.168.56.10  dst=192.168.56.40  dport=3389  bytes=8192  (RDP)
(Internal host connecting to many internal destinations on admin ports)
```

**Detection logic:** Internal source connecting to multiple internal destinations on high-value admin ports (SMB: 445, RDP: 3389, SSH: 22, WinRM: 5985) within a short window.

---

## 5. Suspicious DNS Flow Volume (T1071.004)

**What it looks like in flows:**
```
src=192.168.56.50  dst=8.8.8.8  dport=53  proto=UDP  bytes=200  packets=1
... (500 such flows in 10 minutes from the same host)
```

**Detection logic:** Unusually high number of DNS flows from one host. Could indicate DNS tunneling, malware polling, or DGA (domain generation algorithm) activity.

---

## MITRE ATT&CK Coverage Summary

| Technique                     | ID        | Detection              |
|-------------------------------|-----------|------------------------|
| Network Service Discovery     | T1046     | Port scan pattern      |
| Remote Services               | T1021     | Lateral movement flows |
| Application Layer Protocol    | T1071     | Beaconing pattern      |
| DNS                           | T1071.004 | High DNS flow volume   |
| Exfiltration Over C2          | T1041     | High outbound bytes    |
| Exfiltration Over Web Service | T1567     | HTTP/HTTPS upload      |
| Network Denial of Service     | T1498     | High packet rate       |
