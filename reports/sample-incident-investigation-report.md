# Incident Investigation Report — Beaconing Pattern

**Incident ID:** NETFLOW-LAB-2026-002  
**Author:** Dimas Qi Ramadhani | **Status:** Closed — Lab Test  

---

## 1. Incident Summary

Rule 117003 triggered multiple times for 192.168.56.30 — possible beaconing pattern to 203.0.113.99:443 detected. 8 connections at ~5 minute intervals with consistent byte count (~500 bytes). Investigation confirmed this was the authorized lab synthetic event generator.

---

## 2. Alert Details

| Field | Value |
|-------|-------|
| Rule | 117003 |
| Level | 10 |
| Anomaly | possible_beaconing |
| First seen | 2026-04-25T10:00:00Z |
| Last seen | 2026-04-25T10:35:00Z |

---

## 3. Source IP

`192.168.56.30` — lab-host-03 (dummy)

---

## 4. Destination

`203.0.113.99:443` — external (RFC documentation IP)

---

## 5. Timeline

| Time | Event |
|------|-------|
| T+0 | First connection, 502 bytes, 1.1s |
| T+300 | Second connection, 498 bytes, 0.9s |
| T+600 | Third connection, 511 bytes, 1.2s |
| T+900 | Fourth connection, 505 bytes, 1.0s |
| ... | (8 total connections) |

---

## 6. Analyst Assessment

Lab synthetic test. Interval: 300s ±10s (5 minutes with low jitter). Byte count: 500±20 bytes. Pattern matches C2 check-in behavior. In production: would escalate to endpoint team for process tree analysis on source host.

---

## 7. Response (Production Scenario)

1. Isolate 192.168.56.30 from internet
2. Collect forensic artifacts (memory, process list, network connections)
3. Block 203.0.113.99 at firewall
4. Activate incident response workflow

*Lab report — all data synthetic*
