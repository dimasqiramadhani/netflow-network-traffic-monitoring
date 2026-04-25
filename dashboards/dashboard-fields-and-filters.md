# Wazuh Dashboard — NetFlow Fields and Filters

## Index Pattern: wazuh-alerts-*

## Display Fields for NetFlow Saved Search

| Field | Description |
|-------|-------------|
| @timestamp | Event time |
| agent.name | Collector host |
| data.source.ip | Source IP |
| data.source.port | Source port |
| data.destination.ip | Destination IP |
| data.destination.port | Destination port |
| data.flow.protocol | TCP/UDP/ICMP |
| data.flow.direction | Flow direction |
| data.network.bytes | Bytes transferred |
| data.network.packets | Packet count |
| data.event.duration | Duration (seconds) |
| data.service.name | Service name |
| data.anomaly.tags | Anomaly tags |
| rule.id | Rule ID |
| rule.level | Rule severity level |
| rule.description | Rule description |

## Common Filter Combinations

```
# All NetFlow events
rule.groups:netflow

# Anomalies only
rule.groups:network_anomaly

# High severity
rule.groups:netflow AND rule.level:>=9

# Internal east-west traffic
data.flow.direction:internal_to_internal

# Outbound large transfers
data.flow.direction:internal_to_external AND data.network.bytes:>10000000

# SMB lateral movement candidates
data.destination.port:445 AND data.flow.direction:internal_to_internal

# DNS anomalies
rule.id:117005
```
