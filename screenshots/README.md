# Screenshots Guide — NetFlow Monitoring with Wazuh

> ⚠️ **Redact before committing:** Real IPs, hostnames, usernames.

## Required Screenshots

1. `01-lab-topology.png` — Lab network diagram (hand-drawn or draw.io)
2. `02-wazuh-agent-active.png` — Dashboard showing lab-collector-01 active
3. `03-softflowd-running.png` — `ps aux | grep softflowd` output
4. `04-nfcapd-listening.png` — `ss -ulnp | grep 2055` showing UDP :2055
5. `05-flow-files-created.png` — `ls -lh /var/cache/nfdump/` showing flow files
6. `06-nfdump-output.png` — `nfdump -r <file> -o long | head -10`
7. `07-normalized-json.png` — Sample of netflow-wazuh.json content
8. `08-wazuh-localfile-config.png` — ossec.conf showing localfile configuration
9. `09-decoder-deployed.png` — `ls /var/ossec/etc/decoders/netflow_decoders.xml`
10. `10-rules-deployed.png` — `ls /var/ossec/etc/rules/netflow_rules.xml`
11. `11-wazuh-manager-restart.png` — `systemctl status wazuh-manager` active
12. `12-wazuh-logtest-decoder.png` — wazuh-logtest showing Phase 2 decoder match
13. `13-wazuh-logtest-rule.png` — wazuh-logtest showing Phase 3 rule match
14. `14-dashboard-netflow-filter.png` — Dashboard: `rule.groups:netflow`
15. `15-alert-portscan.png` — Rule 117001 alert detail
16. `16-alert-high-outbound.png` — Rule 117002 alert with bytes field
17. `17-alert-beaconing.png` — Rule 117003 alert
18. `18-alert-lateral-movement.png` — Rule 117004 alert with SMB/RDP port
19. `19-dashboard-source-ip.png` — Top source IP visualization
20. `20-dashboard-dst-port.png` — Destination port distribution
21. `21-dashboard-anomaly-timeline.png` — Anomaly events over time
22. `22-final-report-github.png` — sample-netflow-monitoring-report.md rendered in GitHub
