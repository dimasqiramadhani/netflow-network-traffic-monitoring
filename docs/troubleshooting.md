# Troubleshooting

## pmacctd Not Capturing Traffic

**Symptom:** `/var/log/netflow/netflow_raw.json` is empty or not being created.

**Checks:**
1. Verify pmacctd is running: `ps aux | grep pmacctd | grep -v grep`
2. Check the correct interface: `ip link show` - set `pcap_interface` accordingly
3. Ensure the log directory exists: `ls -la /var/log/netflow/`
4. Run in foreground for debugging: `sudo pmacctd -f /etc/pmacct/pmacctd.conf` (remove `-D` from daemonize or run without config's daemonize)
5. Generate test traffic: `curl -s https://example.com > /dev/null` and check if raw logs appear

**Note:** pmacctd 1.7.6 does not support `print_output_fields`. Use `aggregate` to include `timestamp_start` and `timestamp_end`:
```
aggregate: src_host, dst_host, src_port, dst_port, proto, tos, timestamp_start, timestamp_end
```

## Normalization Script Processed 0 Records

**Symptom:** Script runs but outputs `[+] Processed 0 new records`

**Checks:**
1. Check marker vs raw log line count:
```bash
cat /var/log/netflow/.last_processed_line
wc -l /var/log/netflow/netflow_raw.json
```
2. If marker equals line count, no new data - wait for pmacctd to flush (60 seconds)
3. If marker is larger than line count (log was rotated), reset: `sudo rm -f /var/log/netflow/.last_processed_line`
4. Check raw log has data: `tail -2 /var/log/netflow/netflow_raw.json`

## All Traffic Being Filtered

**Symptom:** Script runs but `skipped` count is very high and `count` is 0 or very low.

**Checks:**
1. Check your `INTERNAL_PREFIX` in the script matches your subnet
2. If your lab uses a different subnet (e.g. `192.168.`), update:
```python
INTERNAL_PREFIX = "192.168."
```
3. Verify what traffic is in the raw log: `tail -10 /var/log/netflow/netflow_raw.json`

## Wazuh Agent Not Forwarding Logs

**Symptom:** Events do not appear on the Wazuh Manager or Dashboard.

**Checks:**
1. Verify agent is connected: check Wazuh Dashboard under **Agents**
2. Check agent log: `sudo tail -50 /var/ossec/logs/ossec.log`
3. Confirm localfile block in `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/netflow/netflow_wazuh.json</location>
</localfile>
```
4. Restart agent after config change: `sudo systemctl restart wazuh-agent`

## Rules Not Triggering Alerts

**Symptom:** Events arrive at Manager but no alerts generated.

**Checks:**
1. Test with wazuh-logtest: `sudo /var/ossec/bin/wazuh-logtest`
2. Paste a sample normalized log line
3. Verify rules file is valid: `sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5`
4. For frequency-based rules (117002, 117004, etc.), a single test event only triggers the base rule (117001)

## OpenSearch Scripted Fields

**Symptom:** Cannot use Sum aggregation on `data.nf_bytes` or `data.nf_packets` in visualizations.

**Cause:** Field type was locked as `string` from initial data ingestion.

**Fix:** Create scripted fields in Stack Management → Index Patterns → wazuh-alerts-* → Scripted fields:

`nf_bytes_num` (number, painless):
```
if (doc['data.nf_bytes'].size() > 0) { return Integer.parseInt(doc['data.nf_bytes'].value) } return 0
```

`nf_packets_num` (number, painless):
```
if (doc['data.nf_packets'].size() > 0) { return Integer.parseInt(doc['data.nf_packets'].value) } return 0
```

Use `nf_bytes_num` and `nf_packets_num` in visualizations instead of the original string fields.

## False Positives

**Common false positive sources:**

| Source                            | Fix                                 |
|-----------------------------------|-------------------------------------|
| Multicast traffic (224.x.x.x)     | Already filtered in script          |
| Broadcast (255.255.255.255)       | Already filtered in script          |
| Internal VM traffic (same subnet) | Set `INTERNAL_PREFIX` correctly     |
| Wazuh agent traffic (port 1514)   | Filtered via internal subnet prefix |
| IPv6 link-local (fe80::)          | Already filtered in script          |

**Rule 117021 (C2 Beaconing) false positives:**
This rule fires on any repeated connections to the same destination. Internal service traffic (monitoring, backups) can trigger it. Add specific IPs to `EXCLUDED_IPS` in the normalization script if needed.
