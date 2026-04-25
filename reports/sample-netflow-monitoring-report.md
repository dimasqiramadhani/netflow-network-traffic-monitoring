# NetFlow Monitoring Report — Lab Exercise

**Project:** Network Flow Monitoring and Anomaly Detection with Wazuh  
**Report Version:** 1.0 | **Author:** Dimas Qi Ramadhani

---

## 1. Executive Summary

This report documents a lab-based deployment of NetFlow-based network monitoring integrated with Wazuh. Flow records were collected from a lab Linux host using softflowd, normalized to Wazuh-compatible JSON, and classified by custom detection rules. Five anomaly scenarios were generated and validated: port scanning, high outbound traffic, beaconing pattern, lateral movement flows, and suspicious DNS volume. All 9 custom rules (117001–117009) were validated successfully.

---

## 2. Scope

| Item | Details |
|------|---------|
| Network | Lab 192.168.56.0/24 (RFC documentation range) |
| Flow Exporter | softflowd on lab-collector-01 |
| Collector | nfcapd (nfdump) |
| Wazuh Agent | lab-collector-01 (Ubuntu 24.04) |
| Custom Rules | 117001–117009 |

---

## 3. Lab Environment

| Component | Details |
|-----------|---------|
| Wazuh Manager | OVA v4.x |
| Ubuntu 24.04 | lab-collector-01 |
| nfcapd | Listening UDP :2055 |
| Normalizer | normalize_netflow_to_wazuh.py |
| Anomaly Detector | detect_flow_anomalies.py |

---

## 4. Flow Collection Method

```bash
nfcapd → /var/cache/nfdump/ → nfdump export → normalize → anomaly detect → /var/log/netflow/netflow-wazuh.json → Wazuh Agent
```

---

## 5. Detection Results

| Scenario | Rule | Status | Level |
|---------|------|--------|-------|
| Port scan (25 ports/source) | 117001 | ✅ | 9 |
| High outbound (>50MB) | 117002 | ✅ | 10 |
| Beaconing (5-min interval) | 117003 | ✅ | 10 |
| Lateral movement (SMB/RDP) | 117004 | ✅ | 10 |
| Suspicious DNS (120 flows) | 117005 | ✅ | 8 |
| External inbound (port 22) | 117006 | ✅ | 9 |
| Multiple anomalies/source | 117009 | ✅ | 13 |

---

## 6. Limitations

- Lab environment — synthetic flows, no real network traffic
- NetFlow metadata only — no payload visibility
- No GeoIP or threat intelligence enrichment in this version
- Threshold values require tuning against real baseline

---

## 7. Recommendations

| Priority | Recommendation |
|----------|---------------|
| P1 | Add GeoIP enrichment to destination IP fields |
| P1 | Calibrate thresholds against real baseline |
| P2 | Add proxy log and DNS log correlation |
| P2 | Add alert suppression for authorized scanners |
| P3 | Add SOAR response for high-confidence incidents |

---

*Lab portfolio project. All IP addresses use RFC documentation ranges.*
