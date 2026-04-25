# Wazuh Dashboard — NetFlow Saved Searches

## 1. NetFlow All Events
- Query: `rule.groups:netflow`
- Columns: timestamp, agent.name, source.ip, destination.ip, destination.port, protocol, bytes, direction, anomaly.tags

## 2. NetFlow Anomalies Only
- Query: `rule.groups:network_anomaly`
- Sort: rule.level descending

## 3. High Outbound Bytes
- Query: `rule.id:117002`
- Purpose: Possible data exfiltration candidates

## 4. Internal Lateral Movement Flows
- Query: `data.flow.direction:internal_to_internal AND rule.id:117004`

## 5. Suspicious DNS Flows
- Query: `rule.id:117005`

## 6. External Inbound Sensitive Services
- Query: `rule.id:117006`

## 7. Port Scan Indicators
- Query: `rule.id:117001`

## 8. Beaconing Indicators
- Query: `rule.id:117003`
