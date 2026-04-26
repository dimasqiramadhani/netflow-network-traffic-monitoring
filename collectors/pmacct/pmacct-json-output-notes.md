# pmacct JSON Output Notes

## Running pmacctd (Direct Interface Capture)

pmacctd captures packets directly from a network interface — no NetFlow exporter
(softflowd/router) is required. This is the collector used in this project.

```bash
# Check interface name first
ip a

# Start pmacctd (replace enp1s0 with your interface)
sudo pmacctd -i enp1s0 \
  -c src_host,dst_host,src_port,dst_port,proto \
  -P print -O json \
  -o /var/log/netflow/netflow-raw.json \
  -r 60 -D

# Or use the provided script
bash collectors/pmacct/pmacct-collector.sh
```

Wait 60 seconds, then verify output:

```bash
cat /var/log/netflow/netflow-raw.json | head -3
```

## pmacctd Output Format

pmacctd with `-c src_host,dst_host,src_port,dst_port,proto` produces:

```json
{"event_type": "purge", "ip_src": "160.22.251.111", "ip_dst": "8.8.8.8", "port_src": 0, "port_dst": 0, "ip_proto": "icmp", "packets": 10, "bytes": 840}
{"event_type": "purge", "ip_src": "192.109.200.50", "ip_dst": "160.22.251.111", "port_src": 47156, "port_dst": 22, "ip_proto": "tcp", "packets": 13, "bytes": 2100}
```

> **Important:** `ip_proto` is output as a **string protocol name** (`"tcp"`, `"udp"`, `"icmp"`, `"igmp"`),
> not a number. The latest normalizer handles both formats.

## Field Reference (pmacctd output in this lab)

| pmacctd Field | Value | Normalized Field |
|--------------|-------|-----------------|
| `ip_src` | Source IP address | `source.ip` |
| `ip_dst` | Destination IP address | `destination.ip` |
| `port_src` | Source port | `source.port` |
| `port_dst` | Destination port | `destination.port` |
| `ip_proto` | Protocol name string (`"tcp"`, `"udp"`, etc.) | `flow.protocol` |
| `packets` | Packet count | `network.packets` |
| `bytes` | Bytes transferred | `network.bytes` |
| `event_type` | Always `"purge"` (flush event) | — (not mapped) |

## Run the Normalizer

```bash
python3 scripts/normalize_netflow_to_wazuh.py \
    --pmacct /var/log/netflow/netflow-raw.json \
    --output /var/log/netflow/netflow-wazuh.json
```

Or automate via cron:

```bash
bash scripts/setup_cron.sh
```
