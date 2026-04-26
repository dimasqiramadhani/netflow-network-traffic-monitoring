# Screenshots Guide — NetFlow Monitoring with Wazuh

> ⚠️ **Redact before committing:** Real IPs, hostnames, usernames.

## Required Screenshots

### Collector Host (VM 2)

1. `01-pmacctd-running.png` — `ps aux | grep pmacctd` showing Core Process + Print Plugin
2. `02-netflow-raw-json.png` — `cat /var/log/netflow/netflow-raw.json | head -5` showing flow records with string ip_proto
3. `03-normalizer-output.png` — output of `python3 scripts/normalize_netflow_to_wazuh.py --pmacct ...` showing `[INFO] Processed: N events | Errors: 0`
4. `04-netflow-wazuh-json.png` — `head -1 /var/log/netflow/netflow-wazuh.json` showing JSON with flow.protocol TCP (not PROTOtcp)
5. `05-cron-setup.png` — `sudo crontab -l` showing normalizer cron running every minute
6. `06-wazuh-localfile-config.png` — `grep -A3 "netflow" /var/ossec/etc/ossec.conf` showing localfile entry
7. `07-wazuh-agent-active.png` — `systemctl status wazuh-agent` showing active (running)

### Wazuh Server (VM 1)

8. `08-decoder-deployed.png` — `ls -la /var/ossec/etc/decoders/netflow_decoders.xml`
9. `09-rules-deployed.png` — `ls -la /var/ossec/etc/rules/netflow_rules.xml`
10. `10-wazuh-manager-active.png` — `systemctl status wazuh-manager` showing active (running)
11. `11-wazuh-logtest-phase2.png` — wazuh-logtest Phase 2: name='json', netflow='true', anomaly tags present
12. `12-wazuh-logtest-phase3.png` — wazuh-logtest Phase 3: id='117001', level='9', Alert to be generated

### Wazuh Dashboard

13. `13-dashboard-netflow-filter.png` — Discover with `rule.groups:netflow` filter, showing 28K+ hits
14. `14-alert-portscan.png` — Expanded event detail for rule 117001 (port scan)
15. `15-alert-high-outbound.png` — Expanded event detail for rule 117002
16. `16-alert-beaconing.png` — Expanded event detail for rule 117003 with groups beaconing, c2_indicator
17. `17-alert-dns.png` — Expanded event detail for rule 117005 with groups dns_anomaly
18. `18-dashboard-rule-breakdown.png` — Bar chart of rule.id counts (117001: 25, 117002: 5, etc.)
19. `19-dashboard-source-ip.png` — Top source IP visualization
20. `20-dashboard-anomaly-timeline.png` — Timeline showing event spike when generate_safe_netflow_test_events.py is run

## Correct Input Format for wazuh-logtest

The input pasted into wazuh-logtest must be **a single raw JSON line** (normalizer output),
not the Wazuh alert JSON format from sample-wazuh-alert-*.json files.

How to get the correct input:

```bash
# Generate an event with anomaly tag
python3 scripts/generate_safe_netflow_test_events.py --scenario port_scan --count 1

# Paste that single output line into wazuh-logtest
```

Example of correct input (single full line):
```json
{"@timestamp": "2026-04-26T11:45:20Z", "netflow": "true", "source": {"ip": "192.168.56.30", "port": 48739}, "destination": {"ip": "192.168.56.28", "port": 47775}, "flow": {"protocol": "TCP", "direction": "internal_to_internal"}, "network": {"bytes": 60, "packets": 1}, "anomaly": {"tags": ["possible_port_scan"]}}
```
