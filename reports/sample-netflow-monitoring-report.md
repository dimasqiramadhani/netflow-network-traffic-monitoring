# NetFlow Monitoring Report — Lab Exercise

**Project:** Network Flow Monitoring and Anomaly Detection with Wazuh  
**Report Version:** 1.0 | **Author:** Dimas Qi Ramadhani

---

## 1. Executive Summary

This report documents a lab-based deployment of NetFlow-based network monitoring integrated with Wazuh. Flow records were collected directly from a lab Linux host network interface using pmacctd, normalized to Wazuh-compatible JSON, and classified by custom detection rules. Five anomaly scenarios were generated and validated: port scanning, high outbound traffic, beaconing pattern, lateral movement flows, and suspicious DNS volume. All 9 custom rules (117001–117009) were validated successfully.

---

## 2. Scope

| Item           | Details                                                |
|----------------|--------------------------------------------------------|
| Network        | Lab 192.168.56.0/24 (RFC documentation range)          |
| Flow Collector | pmacctd on lab-collector-01 (direct interface capture) |
| Wazuh Agent    | lab-collector-01 (Ubuntu 24.04)                        |
| Custom Rules   | 117001–117009                                          |

---

## 3. Lab Environment

| Component        | Details                                   |
|------------------|-------------------------------------------|
| Wazuh Manager    | OVA v4.x                                  |
| Ubuntu 24.04     | lab-collector-01                          |
| pmacctd          | Direct capture on enp1s0, flush every 60s |
| Normalizer       | normalize_netflow_to_wazuh.py             |
| Anomaly Detector | detect_flow_anomalies.py                  |

---

## 4. Flow Collection Method

```bash
pmacctd (enp1s0) → /var/log/netflow/netflow-raw.json → normalize → /var/log/netflow/netflow-wazuh.json → Wazuh Agent
```

---

## 5. Detection Results

| Scenario                    | Rule   | Status | Level |
|-----------------------------|--------|--------|-------|
| Port scan (25 ports/source) | 117001 | Done   | 9     |
| High outbound (>50MB)       | 117002 | Done   | 10    |
| Beaconing (5-min interval)  | 117003 | Done   | 10    |
| Lateral movement (SMB/RDP)  | 117004 | Done   | 10    |
| Suspicious DNS (120 flows)  | 117005 | Done   | 8     |
| External inbound (port 22)  | 117006 | Done   | 9     |
| Multiple anomalies/source   | 117009 | Done   | 13    |

---

## 6. Limitations

- Lab environment — synthetic flows, no real network traffic
- NetFlow metadata only — no payload visibility
- No GeoIP or threat intelligence enrichment in this version
- Threshold values require tuning against real baseline

---

## 7. Recommendations

| Priority | Recommendation                                  |
|----------|-------------------------------------------------|
| P1       | Add GeoIP enrichment to destination IP fields   |
| P1       | Calibrate thresholds against real baseline      |
| P2       | Add proxy log and DNS log correlation           |
| P2       | Add alert suppression for authorized scanners   |
| P3       | Add SOAR response for high-confidence incidents |

---

*Lab portfolio project. All IP addresses use RFC documentation ranges.*
