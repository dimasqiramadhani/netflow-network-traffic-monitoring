# Wazuh Dashboard — NetFlow Fields and Filters

## Index Pattern: wazuh-alerts-*

## Display Fields for NetFlow Saved Search

| Field | Description |
|-------|-------------|
| @timestamp | Event time |
| agent.name | Collector host |
| source.ip | Source IP |
| source.port | Source port |
| destination.ip | Destination IP |
| destination.port | Destination port |
| flow.protocol | TCP/UDP/ICMP/IGMP |
| flow.direction | Flow direction |
| network.bytes | Bytes transferred |
| network.packets | Packet count |
| event.duration | Duration (seconds) |
| service.name | Service name |
| anomaly.tags | Anomaly tags |
| rule.id | Rule ID |
| rule.level | Rule severity level |
| rule.description | Rule description |

> **Note:** Fields above do NOT use the `data.` prefix. With `log_format: json` in
> the Wazuh Agent localfile config, all JSON fields are decoded directly without prefix.
> In older documentation you may see `data.source.ip` etc — those are incorrect for
> this setup and will not match in filters or visualizations.

## Common Filter Combinations

```
# All NetFlow events
rule.groups:netflow

# Anomalies only
rule.groups:network_anomaly

# High severity
rule.groups:netflow AND rule.level:>=9

# Internal east-west traffic
flow.direction:internal_to_internal

# Outbound large transfers
flow.direction:internal_to_external AND network.bytes:>10000000

# SMB lateral movement candidates
destination.port:445 AND flow.direction:internal_to_internal

# DNS anomalies
rule.id:117005

# Port scan
rule.id:117001

# Beaconing / C2
rule.id:117003

# High outbound / exfiltration
rule.id:117002
```
