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

## nfcapd Not Creating Files

```bash
# Check nfcapd is running
ps aux | grep nfcapd

# Verify directory exists and is writable
ls -la /var/cache/nfdump/

# Run nfcapd in foreground verbose mode
sudo nfcapd -D -l /var/cache/nfdump/ -p 2055 -v
```

## nfdump Not Reading Flow Files

```bash
# List files in flow directory
ls -la /var/cache/nfdump/

# Check file format
nfdump -r /var/cache/nfdump/<file> -c 10
```

## pmacct JSON Output Empty

```bash
# Check nfacctd process
ps aux | grep nfacctd

# Check output file
tail -20 /var/log/netflow/pmacct-flows.json

# Check nfacctd logs for errors
journalctl -u nfacctd --since "1 hour ago"
```

## Normalizer Failing

```bash
# Test normalizer manually
python3 scripts/normalize_netflow_to_wazuh.py < samples/sample-nfdump-output.txt | head -5 | python3 -m json.tool
```

## Wazuh Agent Not Reading Log File

```bash
# Verify file exists and has content
ls -la /var/log/netflow/netflow-wazuh.json
tail -5 /var/log/netflow/netflow-wazuh.json | python3 -m json.tool

# Check permissions (Wazuh agent runs as wazuh)
sudo chmod 644 /var/log/netflow/netflow-wazuh.json
```

## Custom Decoder Not Matching

```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a normalized flow event
# Expect: Phase 2 decoder = netflow-json

# Also validate XML
xmllint --noout /var/ossec/etc/decoders/netflow_decoders.xml
```

## Flow Direction Incorrect

Check `INTERNAL_NETWORKS` in your `.env` — if the internal network definition is wrong, all flows will show incorrect direction. Example:

```
# If lab is 192.168.56.0/24 but you set 10.0.0.0/8:
INTERNAL_NETWORKS=192.168.56.0/24,10.10.10.0/24
```

## Too Many Alerts / Too Noisy

- Increase `PORTSCAN_UNIQUE_PORT_THRESHOLD` for port scan rule (default: 20)
- Increase `EXTERNAL_TRAFFIC_THRESHOLD_BYTES` for high outbound rule
- Add known scanner IPs to an allowlist in the normalizer
- Reduce rule level from 9 to 6 for frequent FP rules

## Timezone Mismatch

Ensure collector host, exporter, and Wazuh all use UTC or the same timezone. Check:

```bash
timedatectl
date -u
```
