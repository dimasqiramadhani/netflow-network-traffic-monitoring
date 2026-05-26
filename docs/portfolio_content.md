# Portfolio & Social Content

## GitHub Repository Description (under 160 characters)

Wazuh NetFlow Monitoring PoC - network flow visibility with pmacctd, Python normalization, 24 custom detection rules, validated against real internet traffic.

---

## Short Portfolio Description

**Wazuh NetFlow Monitoring PoC**

Built a working detection pipeline that integrates network flow metadata into Wazuh SIEM using open-source tools on a two-VM architecture.

The pipeline uses pmacctd to capture traffic metadata on a Linux endpoint, a Python normalization script to convert raw flow data into structured flat JSON, and 24 custom Wazuh detection rules covering threats from RDP scanning to DNS exfiltration.

The PoC was validated against real internet traffic on a cloud VM (Eranya Cloud, Ubuntu 22.04). Within hours of deployment, the system detected automated RDP scanners, Telnet crawlers, database port scanners (MySQL, PostgreSQL), NetBIOS broadcasts, and C2 beaconing patterns - generating 4,400+ alerts with 982 at severity level 9 or above.

A custom Wazuh Dashboard with 15+ visualizations was built to monitor alert timelines, threat category breakdowns, attack heatmaps, traffic volume correlations, and top attacker IPs.

Technologies: Wazuh SIEM 4.14, pmacctd 1.7.6, Python 3, OpenSearch Dashboard, custom decoders, custom detection rules, Linux.

---

## LinkedIn Post Caption

Just published a new project: Wazuh NetFlow Monitoring PoC.

I built a detection pipeline that brings network flow visibility into Wazuh SIEM - from raw traffic capture to dashboard alerts - using a simple two-VM setup.

The pipeline:
→ pmacctd captures traffic metadata with timestamps
→ Python script normalizes and filters raw flow data to flat JSON
→ Wazuh Agent forwards normalized logs to the Manager
→ 24 custom detection rules generate alerts across 10 threat categories

I validated this against real internet traffic on a live cloud VM. Within hours:
→ RDP scanner (87.251.64.25) - 4 hits in under 1 second
→ Telnet crawlers from 8 different IPs
→ MySQL and PostgreSQL port scanners from external IPs
→ NetBIOS broadcasts - 2,400+ hits
→ C2 beaconing patterns detected

Total: 4,400+ alerts in ~5 hours, with 982 at severity level 9+

Built a custom Wazuh Dashboard with 15+ visualizations including a threat category heatmap, traffic correlation timeline, and attack detail table.

GitHub: github.com/dimasqiramadhani/wazuh-netflow-monitoring-poc

#Cybersecurity #DetectionEngineering #Wazuh #SIEM #NetworkSecurity #BlueTeam #SOC #OpenSearch

---

## Key Technical Decisions (for interviews)

**Why flat JSON instead of nested?**
Wazuh 4.x does not support dot notation in rule `<field>` tags for nested JSON objects. Discovered this through trial and error during implementation - switched to flat field naming with `nf_` prefix.

**Why integer fields matter?**
OpenSearch locks field types on first ingestion. Initial data was ingested as strings, preventing Sum aggregation in visualizations. Solved with OpenSearch scripted fields as a workaround without reindexing.

**Why filter at the normalization layer?**
Wazuh 4.x does not support `negate="yes"` in `<field>` tags for dynamic JSON fields. Filtering multicast, broadcast, and internal traffic in Python before forwarding to Wazuh was the only reliable approach.

**Why pcre2 in rules?**
Standard regex in Wazuh `<field>` tags caused syntax errors on certain patterns. `type="pcre2"` was required for port matching rules (117003, 117008, 117010, etc.).
