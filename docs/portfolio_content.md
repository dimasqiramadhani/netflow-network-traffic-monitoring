# Portfolio & Social Content

## GitHub Repository Description (under 160 characters)

Wazuh NetFlow Monitoring PoC - network flow visibility with pmacctd, Python normalization, custom decoders, and detection rules on a two-VM architecture.


## Short Portfolio Description

**Wazuh NetFlow Monitoring PoC**

Built a working detection pipeline that integrates network flow metadata into Wazuh SIEM. The project uses pmacctd to capture traffic metadata on a Linux endpoint, a Python script to normalize raw flow data into structured JSON, and custom Wazuh decoders and rules to generate alerts for suspicious network activity - including high connection volume, unusual ports, and external destination detection.

The entire setup runs on two VMs: a Wazuh All-in-One server and a Linux agent that doubles as the NetFlow collector. Five custom detection rules (ID 117001–117005) demonstrate practical detection engineering with Wazuh's rule framework.

Technologies: Wazuh SIEM, pmacctd, Python, JSON log normalization, custom decoders, custom detection rules, Linux.


## LinkedIn Post Caption

Just published a new project: Wazuh NetFlow Monitoring PoC.

I built a detection pipeline that brings network flow visibility into Wazuh SIEM using a simple two-VM lab setup.

The pipeline:
→ pmacctd captures traffic metadata on a Linux endpoint
→ A Python script normalizes raw flow data into structured JSON
→ Custom Wazuh decoders parse the events
→ Custom detection rules generate alerts for suspicious patterns

Detection use cases include high connection volume, unusual destination ports, repeated external connections, and suspicious destination IPs.

Everything runs on two VMs - no complex infrastructure needed.

The repo includes the full configuration, detection rules, sample logs, and documentation.

GitHub: github.com/dimasqiramadhani/wazuh-netflow-monitoring-poc

#Cybersecurity #DetectionEngineering #Wazuh #SIEM #NetworkSecurity #BlueTeam #SOC #InfoSec
