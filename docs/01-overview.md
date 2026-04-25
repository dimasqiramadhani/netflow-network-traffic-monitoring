# 01 — Project Overview

## Project Title

**Network Flow Monitoring and Anomaly Detection with Wazuh**  
*NetFlow/IPFIX Visibility, Wazuh Log Collection, and Flow-Based Detection Engineering*

---

## Executive Summary

This project demonstrates how to build **network flow-based visibility** in a Wazuh SIEM deployment. While endpoint telemetry (Sysmon, auditd) answers "what ran on this host?", NetFlow answers "who was talking to whom, for how long, and how much data moved?" Together, they provide the depth needed for effective threat detection and incident investigation.

---

## What I Learned

| Domain | Skills |
|--------|--------|
| Networking | NetFlow, IPFIX, sFlow protocols and field structure |
| Collector Design | nfdump/nfcapd, pmacct/nfacctd, softflowd |
| Log Engineering | Flow normalization, JSON output, field mapping |
| Wazuh | Custom decoder (JSON_Decoder), custom rules, localfile |
| Detection | Port scan, beaconing, lateral movement, exfiltration indicators |
| Visualization | Dashboard filters, saved searches, threat hunting queries |
| Reporting | Network monitoring report, anomaly detection report |

---

## Catatan (Bahasa Indonesia)

NetFlow adalah teknologi yang mengukur "aliran" komunikasi jaringan — bukan isi paketnya (seperti packet capture), tetapi metadata komunikasinya: siapa yang bicara ke siapa, pakai protokol apa, berapa bytes, berapa lama. Bayangkan NetFlow seperti tagihan telepon yang mencatat siapa yang menelepon siapa dan berapa lama, tanpa merekam isi percakapannya. Ini membuat NetFlow lebih ringan dan lebih privacy-friendly dibanding packet capture, namun tetap sangat berguna untuk mendeteksi anomali perilaku jaringan.
