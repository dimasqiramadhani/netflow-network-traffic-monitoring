# Configuration

This document covers the configuration of three main components: pmacctd, the Python normalization script, and Wazuh Agent log monitoring.

## pmacctd Configuration

File: `/etc/pmacct/pmacctd.conf`

```
! pmacctd configuration for NetFlow PoC
! Tested with pmacctd 1.7.6-git on Ubuntu 22.04

daemonize: true
pcap_interface: enp1s0
plugins: print
print_output: json
print_output_file: /var/log/netflow/netflow_raw.json
print_output_file_append: true
print_refresh_time: 60

! timestamp_start and timestamp_end required for accurate flow timestamps
aggregate: src_host, dst_host, src_port, dst_port, proto, tos, timestamp_start, timestamp_end
```

**Key parameters:**

- `pcap_interface`: Set to your VM's active network interface. Check with `ip link show`.
- `print_output: json`: Outputs flow records in JSON format.
- `print_output_file`: Path where raw flow data is written.
- `print_refresh_time: 60`: Flushes accumulated flow data every 60 seconds.
- `aggregate`: Defines which fields pmacctd tracks. `timestamp_start` and `timestamp_end` are required for accurate timestamps in normalized output.

**Starting pmacctd:**

```bash
sudo pmacctd -f /etc/pmacct/pmacctd.conf
```

**Verifying output:**

```bash
tail -f /var/log/netflow/netflow_raw.json
```

Expected output includes `timestamp_start` field:
```json
{"event_type": "purge", "ip_src": "87.251.64.25", "ip_dst": "160.22.251.9", "port_src": 15844, "port_dst": 3389, "ip_proto": "tcp", "tos": 0, "timestamp_start": "2026-05-26 09:50:32.000000", "timestamp_end": "0000-00-00 00:00:00.000000", "packets": 5, "bytes": 240}
```

## Python Normalization Script

File: `/opt/netflow/normalize_netflow_to_wazuh.py`

The script performs the following:

1. Reads raw JSON records from `/var/log/netflow/netflow_raw.json`.
2. Filters out noise traffic: multicast (224.0.0.0/4), broadcast (255.255.255.255), loopback (127.x.x.x), IPv6 link-local (fe80::), and internal subnet.
3. Parses `timestamp_start` from pmacctd output (supports microsecond format).
4. Renames fields to flat format with `nf_` prefix for Wazuh rule compatibility.
5. Writes each normalized record as a single JSON line to `/var/log/netflow/netflow_wazuh.json`.
6. Tracks the last processed line to avoid reprocessing on each run.

**Internal subnet filter:**

Edit `INTERNAL_PREFIX` in the script to match your environment:

```python
INTERNAL_PREFIX = "160.22."  # adjust to your cloud/lab subnet
```

**Why flat JSON?**

Wazuh 4.x does not support dot notation (e.g. `netflow.dst_port`) in rule `<field>` tags for nested JSON objects. All fields must be at the top level. The script outputs flat JSON with `nf_` prefixed field names.

**Input format** (raw pmacctd output):

```json
{
  "event_type": "purge",
  "ip_src": "87.251.64.25",
  "ip_dst": "160.22.251.9",
  "port_src": 15844,
  "port_dst": 3389,
  "ip_proto": "tcp",
  "timestamp_start": "2026-05-26 09:50:32.000000",
  "timestamp_end": "0000-00-00 00:00:00.000000",
  "packets": 5,
  "bytes": 240
}
```

**Output format** (normalized flat JSON for Wazuh):

```json
{"timestamp":"2026-05-26T09:50:32Z","nf_src_ip":"87.251.64.25","nf_dst_ip":"160.22.251.9","nf_src_port":"15844","nf_dst_port":"3389","nf_protocol":"tcp","nf_packets":"5","nf_bytes":"240","nf_duration":"0"}
```

## Cron Job

Run the normalization script every minute:

```bash
sudo crontab -e
```

Add:
```
* * * * * /usr/bin/python3 /opt/netflow/normalize_netflow_to_wazuh.py
```

## Wazuh Agent Configuration

On VM 2, add the following `localfile` block to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/netflow/netflow_wazuh.json</location>
</localfile>
```

Restart the agent after any config change:

```bash
sudo systemctl restart wazuh-agent
```

## Wazuh Rules Configuration

Copy the rules file to the Wazuh Manager:

```bash
sudo cp rules/rules/netflow_rules.xml /var/ossec/etc/rules/netflow_rules.xml
```

Test configuration before restarting:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5
```

Restart the Manager:

```bash
sudo systemctl restart wazuh-manager
```

## Log Rotation

Prevent log files from growing indefinitely:

```bash
sudo tee /etc/logrotate.d/netflow << 'EOF'
/var/log/netflow/*.json {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
