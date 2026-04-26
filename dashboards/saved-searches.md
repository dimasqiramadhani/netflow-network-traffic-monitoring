# Wazuh Dashboard — NetFlow Saved Searches

> **Note:** Fields use nested JSON. In Wazuh Dashboard all fields appear with the `data.` prefix
> (e.g. `data.source.ip`, `data.flow.direction`, `data.anomaly.tags`).

## 1. NetFlow All Events
- Query: `rule.groups:netflow`
- Columns: timestamp, agent.name, data.source.ip, data.destination.ip, data.destination.port, data.flow.protocol, data.network.bytes, data.flow.direction, data.anomaly.tags

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

## 6. External Inbound to Sensitive Services
- Query: `rule.id:117006`

## 7. Port Scan Indicators
- Query: `rule.id:117001`

## 8. Beaconing Indicators
- Query: `rule.id:117003`
