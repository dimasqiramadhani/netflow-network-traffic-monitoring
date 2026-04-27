# 01 — Project Overview

## Project Title

**Network Flow Monitoring and Anomaly Detection with Wazuh**  
*NetFlow/IPFIX Visibility, Wazuh Log Collection, and Flow-Based Detection Engineering*

---

## Executive Summary

This project demonstrates how to build **network flow-based visibility** in a Wazuh SIEM deployment. While endpoint telemetry (Sysmon, auditd) answers "what ran on this host?", NetFlow answers "who was talking to whom, for how long, and how much data moved?" Together, they provide the depth needed for effective threat detection and incident investigation.

---

## What I Learned

| Domain           | Skills                                                          |
|------------------|-----------------------------------------------------------------|
| Networking       | NetFlow, IPFIX, sFlow protocols and field structure             |
| Collector Design | pmacctd (direct interface capture), pipeline normalization      |
| Log Engineering  | Flow normalization, JSON output, field mapping                  |
| Wazuh            | Custom decoder (JSON_Decoder), custom rules, localfile          |
| Detection        | Port scan, beaconing, lateral movement, exfiltration indicators |
| Visualization    | Dashboard filters, saved searches, threat hunting queries       |
| Reporting        | Network monitoring report, anomaly detection report             |

---

## Key Concept

NetFlow is a technology that measures network communication "flows" — not the packet contents (like packet capture), but the communication metadata: who spoke to whom, using what protocol, how many bytes, for how long. Think of NetFlow like a phone bill that records who called whom and for how long, without recording the conversation itself. This makes NetFlow lighter and more privacy-friendly than full packet capture, while still being highly useful for detecting behavioral anomalies on the network.
