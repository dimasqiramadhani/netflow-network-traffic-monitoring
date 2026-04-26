# Screenshots Guide — NetFlow Monitoring with Wazuh

> ⚠️ **Redact before committing:** Real IPs, hostnames, usernames.

## Required Screenshots

### Collector Host (VM 2)

1. `01-pmacctd-running.png` — `ps aux | grep pmacctd` showing Core Process + Print Plugin
2. `02-netflow-raw-json.png` — `cat /var/log/netflow/netflow-raw.json | head -5` showing flow records dengan ip_proto string
3. `03-normalizer-output.png` — output dari `python3 scripts/normalize_netflow_to_wazuh.py --pmacct ...` menunjukkan `[INFO] Processed: N events | Errors: 0`
4. `04-netflow-wazuh-json.png` — `head -1 /var/log/netflow/netflow-wazuh.json` menunjukkan JSON dengan flow.protocol TCP (bukan PROTOtcp)
5. `05-cron-setup.png` — `sudo crontab -l` showing normalizer cron setiap menit
6. `06-wazuh-localfile-config.png` — `grep -A3 "netflow" /var/ossec/etc/ossec.conf` showing localfile entry
7. `07-wazuh-agent-active.png` — `systemctl status wazuh-agent` showing active (running)

### Wazuh Server (VM 1)

8. `08-decoder-deployed.png` — `ls -la /var/ossec/etc/decoders/netflow_decoders.xml`
9. `09-rules-deployed.png` — `ls -la /var/ossec/etc/rules/netflow_rules.xml`
10. `10-wazuh-manager-active.png` — `systemctl status wazuh-manager` showing active (running)
11. `11-wazuh-logtest-phase2.png` — wazuh-logtest Phase 2: name='json', source='netflow', anomaly.tags terisi
12. `12-wazuh-logtest-phase3.png` — wazuh-logtest Phase 3: id='117001', level='9', Alert to be generated

### Wazuh Dashboard

13. `13-dashboard-netflow-filter.png` — Dashboard Discover dengan filter `rule.groups:netflow`, tampil 28K+ hits
14. `14-alert-portscan.png` — Detail event rule 117001 di dashboard (klik expand salah satu event)
15. `15-alert-high-outbound.png` — Detail event rule 117002
16. `16-alert-beaconing.png` — Detail event rule 117003 dengan groups beaconing, c2_indicator
17. `17-alert-dns.png` — Detail event rule 117005 dengan groups dns_anomaly
18. `18-dashboard-rule-breakdown.png` — Bar chart rule.id count (117001: 25, 117002: 5, dll)
19. `19-dashboard-source-ip.png` — Top source IP visualization
20. `20-dashboard-anomaly-timeline.png` — Timeline: lonjakan event saat generate_safe_netflow_test_events.py dijalankan

## Cara Ambil Screenshot yang Benar untuk wazuh-logtest

Input yang di-paste ke wazuh-logtest adalah **satu baris dari netflow-wazuh.json** (output normalizer),
bukan dari file sample-wazuh-alert-*.json.

Cara mendapatkan input yang tepat:

```bash
# Generate event dengan anomaly tag
python3 scripts/generate_safe_netflow_test_events.py --scenario port_scan --count 1

# Output satu baris itu yang di-paste ke wazuh-logtest
```

Contoh input yang benar (satu baris penuh):
```json
{"@timestamp": "2026-04-26T11:45:20Z", "source": "netflow", "collector.name": "lab-collector-01", "exporter.ip": "192.168.56.1", "flow.protocol": "TCP", "source.ip": "192.168.56.30", "source.port": "48739", "destination.ip": "192.168.56.28", "destination.port": "47775", "network.bytes": 60, "network.packets": 1, "event.duration": 0.001, "tcp.flags": "SYN", "flow.direction": "internal_to_internal", "internal.src": true, "internal.dst": true, "service.name": "OTHER", "event.type": "network", "event.category": "network_traffic", "anomaly.tags": ["possible_port_scan"]}
```
