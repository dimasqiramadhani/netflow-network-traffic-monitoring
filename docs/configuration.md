# Configuration

This document covers the configuration of three main components: pmacctd, the Python normalization script, and Wazuh Agent log monitoring.

## pmacctd Configuration

File: `/etc/pmacct/pmacctd.conf`

```
! pmacctd configuration for NetFlow PoC
daemonize: true
pcap_interface: ens33
plugins: print
print_output: json
print_output_file: /var/log/netflow/netflow_raw.json
print_output_file_append: true
print_refresh_time: 60
aggregate: src_host, dst_host, src_port, dst_port, proto, tos
```

**Key parameters:**

- `pcap_interface`: Set this to your VM's active network interface (e.g., `ens33`, `eth0`, `ens18`). Check with `ip link show`.
- `print_output: json`: Outputs flow records in JSON format.
- `print_output_file`: Path where raw flow data is written.
- `print_refresh_time: 60`: Flushes accumulated flow data every 60 seconds.
- `aggregate`: Defines which fields pmacctd tracks per flow record.

**Note:** The interface name depends on your VM's network configuration. Adjust `pcap_interface` accordingly.

## Python Normalization Script

File: `/opt/netflow/normalize_netflow_to_wazuh.py`

The script performs the following:

1. Reads raw JSON records from `/var/log/netflow/netflow_raw.json`.
2. Renames fields to a consistent naming convention (`ip_src` → `src_ip`, `ip_dst` → `dst_ip`, etc.).
3. Converts timestamps to ISO 8601 format.
4. Calculates flow duration in seconds from `stamp_inserted` and `stamp_updated`.
5. Writes each normalized record as a single JSON line to `/var/log/netflow/netflow_wazuh.json`.

**Input format** (raw pmacctd output):

```json
{
  "event_type": "purge",
  "ip_src": "192.168.10.15",
  "ip_dst": "185.220.101.34",
  "port_src": 49832,
  "port_dst": 443,
  "ip_proto": "tcp",
  "packets": 12,
  "bytes": 3456,
  "stamp_inserted": "2025-01-15 10:32:01",
  "stamp_updated": "2025-01-15 10:32:30"
}
```

**Output format** (normalized for Wazuh):

```json
{"timestamp":"2025-01-15T10:32:01Z","netflow":{"src_ip":"192.168.10.15","dst_ip":"185.220.101.34","src_port":49832,"dst_port":443,"protocol":"tcp","packets":12,"bytes":3456,"duration_sec":29}}
```

Each output line is a single JSON object. Wazuh reads each line as one event.

## Wazuh Agent Configuration

On VM 2, add the following `localfile` block to `/var/ossec/etc/ossec.conf` inside the `<ossec_config>` section:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/netflow/netflow_wazuh.json</location>
</localfile>
```

This tells the Wazuh Agent to:
- Monitor the normalized JSON log file.
- Parse each line as a JSON event.
- Forward each event to the Wazuh Manager.

After adding this configuration, restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

## Wazuh Manager Configuration

No changes to the Manager's `ossec.conf` are required for this PoC. The custom decoder and rules are placed in:

- `/var/ossec/etc/decoders/netflow_decoder.xml`
- `/var/ossec/etc/rules/netflow_rules.xml`

The Manager automatically loads decoders and rules from these directories on restart.

Restart the Manager after placing the files:

```bash
sudo systemctl restart wazuh-manager
```

## Log Rotation

To prevent log files from growing indefinitely, configure logrotate for the NetFlow logs:

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
EOF
```

This rotates logs daily and keeps seven days of history.
