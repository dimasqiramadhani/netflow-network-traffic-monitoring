# 13 — Dashboard and Threat Hunting Queries

## Wazuh Dashboard Filters

### General NetFlow

| Filter                        | Purpose                 |
|-------------------------------|-------------------------|
| `rule.groups:netflow`         | All NetFlow events      |
| `rule.groups:network_anomaly` | Detected anomalies only |
| `rule.level:>=8`              | High severity alerts    |

### Port Scanning

| Filter                            | Purpose          |
|-----------------------------------|------------------|
| `rule.id:117001`                  | Port scan alerts |
| `anomaly.tags:possible_port_scan` | Tag-based filter |

### High Outbound Traffic

| Filter                                | Purpose            |
|---------------------------------------|--------------------|
| `rule.id:117002`                      | High outbound rule |
| `flow.direction:internal_to_external` | Outbound flows     |
| `network.bytes:>50000000`             | Large transfers    |

### Beaconing

| Filter                            | Purpose          |
|-----------------------------------|------------------|
| `rule.id:117003`                  | Beaconing alerts |
| `anomaly.tags:possible_beaconing` | Tag filter       |

### Lateral Movement

| Filter                                | Purpose               |
|---------------------------------------|-----------------------|
| `rule.id:117004`                      | Lateral movement rule |
| `destination.port:445`                | SMB traffic           |
| `destination.port:3389`               | RDP traffic           |
| `destination.port:5985`               | WinRM traffic         |
| `flow.direction:internal_to_internal` | East-west traffic     |

### DNS

| Filter                | Purpose             |
|-----------------------|---------------------|
| `rule.id:117005`      | Suspicious DNS rule |
| `destination.port:53` | DNS port            |
| `service.name:DNS`    | DNS service name    |

### MITRE

| Filter                | Technique                  |
|-----------------------|----------------------------|
| `rule.mitre.id:T1046` | Network Service Discovery  |
| `rule.mitre.id:T1021` | Remote Services            |
| `rule.mitre.id:T1071` | Application Layer Protocol |
| `rule.mitre.id:T1041` | Exfiltration Over C2       |
| `rule.mitre.id:T1498` | Network Denial of Service  |

## Combined Hunting Queries

```
# All network anomalies in last 24 hours
rule.groups:network_anomaly AND @timestamp:[now-24h TO now]

# High-severity flows from specific source
rule.groups:netflow AND rule.level:>=9 AND source.ip:192.0.2.10

# Internal lateral movement candidates
flow.direction:internal_to_internal AND destination.port:(445 OR 3389 OR 22 OR 5985)

# Potential exfiltration (>10MB outbound)
flow.direction:internal_to_external AND network.bytes:>10000000
```
