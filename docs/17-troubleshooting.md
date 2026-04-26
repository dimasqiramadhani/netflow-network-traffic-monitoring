# 17 — Troubleshooting

## Collector Not Receiving Flows

```bash
# Check UDP port is listening
ss -ulnp | grep 2055

# Check firewall
sudo ufw status | grep 2055
# or
sudo iptables -L -n | grep 2055

# Test with netcat from exporter host
echo "test" | nc -u <collector-ip> 2055
```

## pmacct JSON Output Empty

```bash
# Check pmacctd process
ps aux | grep pmacctd

# Check output file
tail -20 /var/log/netflow/netflow-raw.json

# Check logs for errors
journalctl -u pmacctd --since "1 hour ago"
```

## Normalizer Failing

```bash
# Test normalizer manually with a sample pmacct record
echo '{"ip_src":"1.1.1.1","ip_dst":"2.2.2.2","port_src":1234,"port_dst":443,"ip_proto":"tcp","packets":1,"bytes":100}' \
  > /tmp/test-pmacct.json

python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /tmp/test-pmacct.json \
  --output /tmp/test-out.json

cat /tmp/test-out.json | python3 -m json.tool
```

## Wazuh Agent Not Reading Log File

```bash
# Verify file exists and has content
ls -la /var/log/netflow/netflow-wazuh.json
tail -5 /var/log/netflow/netflow-wazuh.json | python3 -m json.tool

# Fix permissions (Wazuh agent needs read access)
sudo chmod 644 /var/log/netflow/netflow-wazuh.json
```

## Custom Decoder Not Matching

```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a normalized flow event (single JSON line from netflow-wazuh.json)
# Expected Phase 2: name='json', netflow='true'

# Validate XML syntax
xmllint --noout /var/ossec/etc/decoders/netflow_decoders.xml
```

## Flow Direction Incorrect

Check `INTERNAL_NETWORKS` in your `.env` — if the internal network definition does not match your actual lab subnet, all flows will show incorrect direction.

```bash
# Check actual VM IP and subnet
ip a | grep "inet " | grep -v 127

# Update .env accordingly
echo 'INTERNAL_NETWORKS=160.22.250.0/23' > .env
```

## Too Many Alerts / Too Noisy

- Increase `PORTSCAN_UNIQUE_PORT_THRESHOLD` (default: 20) to reduce port scan sensitivity
- Increase `EXTERNAL_TRAFFIC_THRESHOLD_BYTES` to raise the high outbound threshold
- Add known scanner IPs to an allowlist in the normalizer
- Reduce rule level from 9 to 6 for frequent false-positive rules

## Timezone Mismatch

Ensure the collector host, exporter, and Wazuh all use UTC or the same timezone:

```bash
timedatectl
date -u
```

---

## Wazuh Manager Fails to Start After Deploying Decoder

**Symptom:**
```
wazuh-analysisd: ERROR: Invalid decoder type 'json'
wazuh-analysisd: CRITICAL: (1202): Configuration error at 'etc/decoders/netflow_decoders.xml'
```

**Cause:** `<type>json</type>` is not valid in Wazuh v4.x.

**Fix:** Ensure you are using the latest `netflow_decoders.xml` — the `<type>json</type>` tag has been removed. JSON parsing is handled by `log_format: json` in the agent's ossec.conf localfile config, not in the decoder.

```bash
# Verify decoder has no type tag
grep "type" /var/ossec/etc/decoders/netflow_decoders.xml
# Should return no output

sudo systemctl restart wazuh-manager
```

---

## Alerts Appear but rule.id is Only 117010 (No 117001-117008)

**Symptom:** NetFlow events appear in the dashboard but only rule 117010 (base visibility) fires.

**Cause:** Rules 117001-117008 used `data.anomaly.tags`, `data.flow.direction`, etc. With `log_format: json`, the actual field names are without the `data.` prefix — e.g. `anomaly.tags`, `flow.direction`.

**Fix:** Ensure you are using the latest `netflow_rules.xml` which removes the `data.` prefix from all field names.

```bash
# Verify no data. prefix in rules
grep "data\." /var/ossec/etc/rules/netflow_rules.xml
# Should return no output

sudo systemctl restart wazuh-manager

# Test with wazuh-logtest
sudo /var/ossec/bin/wazuh-logtest
# Paste event with anomaly.tags containing possible_port_scan
# Phase 3 should show rule id: '117001'
```

---

## flow.protocol Shows PROTOtcp Instead of TCP

**Symptom:** In Wazuh Dashboard, `flow.protocol` shows `PROTOtcp`, `PROTOudp`, etc.

**Cause:** pmacctd outputs `ip_proto` as a string protocol name (`"tcp"`, `"udp"`, `"igmp"`), not a number (`"6"`, `"17"`). The old normalizer only handled numeric values.

**Fix:** Use the latest `normalize_netflow_to_wazuh.py` which handles both string and numeric protocol formats.

```bash
# Test normalizer
echo '{"ip_src":"1.1.1.1","ip_dst":"2.2.2.2","port_src":1234,"port_dst":443,"ip_proto":"tcp","packets":1,"bytes":100}' \
  > /tmp/test-pmacct.json

python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /tmp/test-pmacct.json --output /tmp/test-out.json

python3 -c "import json; d=json.load(open('/tmp/test-out.json')); print(d['flow']['protocol'])"
# Expected output: TCP
```

---

## softflowd / nfcapd: "No matched flows"

**Symptom:** nfcapd is running, softflowd is running, but `nfdump -R /var/cache/nfdump/` always returns "No matched flows".

**Cause:** In cloud VM environments (OpenStack, AWS, GCP, etc.), traffic is processed at the hypervisor level before reaching the interface. softflowd uses libpcap and cannot correctly capture byte/packet counters — resulting in empty flow records.

**Fix:** Use pmacctd as the collector instead of nfcapd/softflowd:

```bash
sudo pkill nfcapd
sudo pkill softflowd

# Check interface name
ip a

# Start pmacctd directly from interface
sudo pmacctd -i enp1s0 \
  -c src_host,dst_host,src_port,dst_port,proto \
  -P print -O json \
  -o /var/log/netflow/netflow-raw.json \
  -r 60 -D

# Wait 65 seconds then verify
cat /var/log/netflow/netflow-raw.json | head -3
```

Or use the provided script:
```bash
bash collectors/pmacct/pmacct-collector.sh
```

---

## Localfile Duplicate in ossec.conf

**Symptom:**
```
WARNING: (1958): Log file '/var/log/netflow/netflow-wazuh.json' is duplicated.
```

**Cause:** The localfile entry was added more than once to ossec.conf.

**Fix:**
```bash
# Check for duplicates
grep -n "netflow" /var/ossec/etc/ossec.conf

# Edit manually and remove one of the duplicate blocks
sudo nano /var/ossec/etc/ossec.conf

# Confirm only one entry remains
grep -c "netflow-wazuh.json" /var/ossec/etc/ossec.conf
# Expected output: 1

sudo systemctl restart wazuh-agent
```

---

## Custom Decoder Shows name: 'json' Instead of 'netflow-json' in Phase 2

**This is normal and expected.** With `log_format: json` in localfile config, Wazuh automatically uses the built-in json decoder. The custom decoder `netflow-json` is used only as an anchor for rule 117000 (`<decoded_as>json</decoded_as>`). What matters is that Phase 3 shows the correct rule — not the decoder name.

---

## Correct Input Format for wazuh-logtest

**Symptom:** wazuh-logtest does not match decoder or Phase 3 does not appear despite correct rules.

**Cause:** The pasted input is not in the correct format. wazuh-logtest accepts **a single raw JSON line** (normalizer output), not the Wazuh alert JSON format.

**Wrong input** (this is a Wazuh alert, not logtest input):
```json
{
  "rule": {"id": "117001"},
  "data": {"source.ip": "..."},
  ...
}
```

**Correct input** (single line from normalizer output):
```bash
# Generate with:
python3 scripts/generate_safe_netflow_test_events.py --scenario port_scan --count 1

# Paste the output line into wazuh-logtest, example:
{"@timestamp": "2026-04-26T11:45:20Z", "netflow": "true", "source": {"ip": "192.168.56.30", "port": 48739}, "destination": {"ip": "192.168.56.28", "port": 47775}, "flow": {"protocol": "TCP", "direction": "internal_to_internal"}, "network": {"bytes": 60, "packets": 1}, "anomaly": {"tags": ["possible_port_scan"]}}
```

---

## generate_safe_netflow_test_events.py Produces No Alerts

**Symptom:** Test event generation succeeds but no 117001-117005 alerts appear in dashboard.

**Most common cause:** The cron normalizer is still active and overwrites the file every minute before Wazuh Agent can read all the events.

**Fix:**
```bash
# 1. Pause cron first
sudo crontab -e  # add # at the start of the normalizer line

# 2. Generate test events
python3 scripts/generate_safe_netflow_test_events.py \
  --scenario all \
  --output /var/log/netflow/netflow-wazuh.json

# 3. Wait 30 seconds for Wazuh Agent to pick up the file

# 4. Check alerts on VM 1
sudo grep -E '"id":"11700[1-9]"' /var/ossec/logs/alerts/alerts.json | tail -5

# 5. Re-enable cron after testing
sudo crontab -e  # remove the #
```

---

## source.ip / destination.ip Missing in Wazuh Dashboard

**Symptom:** `source.ip` field does not appear or is empty in Wazuh Dashboard despite events being ingested.

**Cause:** The old normalizer used flat dot-notation keys like `"source.ip": "x.x.x.x"`. Wazuh JSON_Decoder treats dots as nested object separators. Since `"source"` was also used as the string `"netflow"`, a conflict occurred — Wazuh could not decode `source` as both a string and a nested object parent.

**Fix:** The latest normalizer uses proper nested JSON:

```json
{
  "source": {"ip": "192.168.56.10", "port": 52341},
  "destination": {"ip": "8.8.8.8", "port": 443},
  "flow": {"protocol": "TCP", "direction": "internal_to_external"}
}
```

With this structure, fields appear in Wazuh Dashboard as:
- `data.source.ip` → source IP
- `data.destination.ip` → destination IP
- `data.flow.protocol` → protocol
- `data.anomaly.tags` → anomaly tags

Use the latest `normalize_netflow_to_wazuh.py` and regenerate `netflow-wazuh.json`:

```bash
rm -f /var/log/netflow/netflow-wazuh.json
python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /var/log/netflow/netflow-raw.json \
  --output /var/log/netflow/netflow-wazuh.json

# Verify nested format
head -1 /var/log/netflow/netflow-wazuh.json | python3 -m json.tool | grep -A2 '"source"'
# Expected:
# "source": {
#     "ip": "x.x.x.x",
```

---

## data.network.bytes Not Available for Sum Aggregation in Dashboard

**Symptom:** `data.network.bytes` does not appear in the aggregation Sum dropdown in Visualize, or appears but cannot be selected for Sum/Avg.

**Cause:** Wazuh Indexer stores the field as type `keyword` (string) instead of `long` (number). Numeric fields must be defined in an index template before data is ingested.

**Fix — Apply index template (run on VM 1):**

```bash
curl -k -u admin:<password> \
  -X PUT "https://localhost:9200/_index_template/wazuh-netflow-numeric" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["wazuh-alerts-*"],
    "priority": 200,
    "template": {
      "mappings": {
        "properties": {
          "data.network.bytes":   {"type": "long"},
          "data.network.packets": {"type": "long"}
        }
      }
    }
  }'
```

This template applies to **new indexes** created after this point. Existing indexes cannot be changed.

After a new index is created:
1. **Stack Management → Index Patterns → wazuh-alerts-* → Refresh field list**
2. Try Sum aggregation on `data.network.bytes` again

---

## All Traffic Shows external_to_external on Real Traffic

**Symptom:** All traffic from pmacctd is classified as `external_to_external`, rule 117004 never fires.

**Cause:** `INTERNAL_NETWORKS` in the normalizer still uses the default `192.168.56.0/24` but the actual VM IP is on a different subnet (e.g. `160.22.250.0/23`).

**Fix:**

```bash
# Check your VM subnet
ip a | grep "inet " | grep -v 127

# Set environment variable before running normalizer
export INTERNAL_NETWORKS="160.22.250.0/23"

# Or add to .env file in project folder
echo 'INTERNAL_NETWORKS=160.22.250.0/23' >> .env

# Regenerate netflow-wazuh.json
rm -f /var/log/netflow/netflow-wazuh.json
python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /var/log/netflow/netflow-raw.json \
  --output /var/log/netflow/netflow-wazuh.json

# Verify flow.direction is correct
head -5 /var/log/netflow/netflow-wazuh.json | \
  python3 -c "import sys,json; [print(json.loads(l)['flow']['direction']) for l in sys.stdin]"
```

Also update cron to pass the environment variable:

```bash
sudo crontab -e
# Update the cron line to:
# * * * * * INTERNAL_NETWORKS=160.22.250.0/23 rm -f /var/log/netflow/netflow-wazuh.json && python3 /path/to/normalize_netflow_to_wazuh.py --pmacct /var/log/netflow/netflow-raw.json --output /var/log/netflow/netflow-wazuh.json
```
