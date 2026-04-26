# Wazuh Dashboard — NetFlow Visualization Guide

> **Note:** Fields use nested JSON. In Wazuh Dashboard prefix all fields with `data.`
> (e.g. `data.source.ip`, `data.flow.direction`, `data.anomaly.tags`).

## 1. Alert Count per Rule ID (Horizontal Bar)
- Query: `rule.groups:netflow AND rule.id:[117001 TO 117009]`
- Y-axis: Count
- X-axis: Terms → `rule.id` → Top 10 → Order by Count desc
- Purpose: "Which detection rules fired the most?"

## 2. Top Source IPs (Data Table)
- Query: `rule.groups:netflow`
- Metric: Count
- Bucket: Terms on `source.ip`
- Size: 10
- Purpose: "Who is generating the most network activity?"

## 3. Top Destination IPs by Bytes (Data Table)
- Query: `rule.groups:netflow`
- Metric: Sum of `network.bytes`
- Bucket: Terms on `destination.ip`
- Purpose: "Which destinations receive the most data?"

## 4. Protocol Distribution (Pie)
- Query: `rule.groups:netflow`
- Slice size: Count
- Split slices: Terms on `flow.protocol` → Top 5
- Purpose: "What mix of protocols is seen?"

## 5. Flow Direction Distribution (Pie)
- Query: `rule.groups:netflow`
- Bucket: Terms on `flow.direction`
- Purpose: "What ratio of east-west vs. north-south traffic?"

## 6. Destination Port Distribution (Bar)
- Query: `rule.groups:netflow AND rule.id:[117001 TO 117009]`
- Y-axis: Count
- X-axis: Terms on `destination.port` → Top 10
- Purpose: "Which services are being accessed in anomalous flows?"

## 7. NetFlow Anomaly Timeline (Area / Bar)
- Query: `rule.groups:network_anomaly`
- Y-axis: Count
- X-axis: Date histogram → `@timestamp` → Auto interval
- Purpose: "When are anomalies happening?"

## 8. High Outbound Bytes Over Time (Line)
- Query: `rule.id:117002`
- Y-axis: Sum of `network.bytes`
- X-axis: Date histogram
- Purpose: "Is outbound volume increasing?"

## 9. Lateral Movement Candidates (Data Table)
- Query: `flow.direction:internal_to_internal AND destination.port:(445 OR 3389 OR 22 OR 5985)`
- Fields: source.ip, destination.ip, destination.port, network.bytes
- Purpose: "Which hosts are accessing admin services internally?"
