# 13 — Dashboard and Threat Hunting Queries

## Wazuh Dashboard Filters

### General NetFlow

| Filter | Purpose |
|--------|---------|
| `rule.groups:netflow` | All NetFlow events |
| `rule.groups:network_anomaly` | Detected anomalies only |
| `rule.level:>=8` | High severity alerts |

### Port Scanning

| Filter | Purpose |
|--------|---------|
| `rule.id:117001` | Port scan alerts |
| `data.anomaly.tags:possible_port_scan` | Tag-based filter |

### High Outbound Traffic

| Filter | Purpose |
|--------|---------|
| `rule.id:117002` | High outbound rule |
| `data.flow.direction:internal_to_external` | Outbound flows |
| `data.network.bytes:>50000000` | Large transfers |

### Beaconing

| Filter | Purpose |
|--------|---------|
| `rule.id:117003` | Beaconing alerts |
| `data.anomaly.tags:possible_beaconing` | Tag filter |

### Lateral Movement

| Filter | Purpose |
|--------|---------|
| `rule.id:117004` | Lateral movement rule |
| `data.destination.port:445` | SMB traffic |
| `data.destination.port:3389` | RDP traffic |
| `data.destination.port:5985` | WinRM traffic |
| `data.flow.direction:internal_to_internal` | East-west traffic |

### DNS

| Filter | Purpose |
|--------|---------|
| `rule.id:117005` | Suspicious DNS rule |
| `data.destination.port:53` | DNS port |
| `data.service.name:DNS` | DNS service name |

### MITRE

| Filter | Technique |
|--------|-----------|
| `rule.mitre.id:T1046` | Network Service Discovery |
| `rule.mitre.id:T1021` | Remote Services |
| `rule.mitre.id:T1071` | Application Layer Protocol |
| `rule.mitre.id:T1041` | Exfiltration Over C2 |
| `rule.mitre.id:T1498` | Network Denial of Service |

## Combined Hunting Queries

```
# All network anomalies in last 24 hours
rule.groups:network_anomaly AND @timestamp:[now-24h TO now]

# High-severity flows from specific source
rule.groups:netflow AND rule.level:>=9 AND data.source.ip:192.0.2.10

# Internal lateral movement candidates
data.flow.direction:internal_to_internal AND data.destination.port:(445 OR 3389 OR 22 OR 5985)

# Potential exfiltration (>10MB outbound)
data.flow.direction:internal_to_external AND data.network.bytes:>10000000
```
