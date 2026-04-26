# Wazuh Dashboard — NetFlow Visualization Guide

> **Note:** Fields use nested JSON. In Wazuh Dashboard all fields appear with the `data.` prefix
> (e.g. `data.source.ip`, `data.flow.direction`, `data.anomaly.tags`).

## 1. Alert Count per Rule ID (Horizontal Bar)
- Query: `rule.groups:netflow AND rule.id:[117001 TO 117009]`
- Y-axis: Count
- X-axis: Terms → `rule.id` → Top 10 → Order by Count desc
- Purpose: "Which detection rules fired the most?"

## 2. Top Source IPs (Data Table)
- Query: `rule.groups:netflow`
- Metric: Count
- Bucket: Terms on `data.source.ip`
- Size: 10
- Purpose: "Who is generating the most network activity?"

## 3. Top Destination IPs by Bytes (Data Table)
- Query: `rule.groups:netflow`
- Metric: Sum of `data.network.bytes`
- Bucket: Terms on `data.destination.ip`
- Purpose: "Which destinations receive the most data?"

## 4. Protocol Distribution (Pie)
- Query: `rule.groups:netflow`
- Slice size: Count
- Split slices: Terms on `data.flow.protocol` → Top 5
- Purpose: "What mix of protocols is seen?"

## 5. Flow Direction Distribution (Pie)
- Query: `rule.groups:netflow`
- Bucket: Terms on `data.flow.direction`
- Purpose: "What ratio of east-west vs. north-south traffic?"

## 6. Destination Port Distribution (Bar)
- Query: `rule.groups:netflow AND rule.id:[117001 TO 117009]`
- Y-axis: Count
- X-axis: Terms on `data.destination.port` → Top 10
- Purpose: "Which services are being accessed in anomalous flows?"

## 7. NetFlow Anomaly Timeline (Area / Bar)
- Query: `rule.id:[117001 TO 117009]`
- Y-axis: Count
- X-axis: Date histogram → `@timestamp` → Auto interval
- Purpose: "When are anomalies happening?"

## 8. High Outbound Bytes Over Time (Line)
- Query: `rule.id:117002`
- Y-axis: Sum of `data.network.bytes`
- X-axis: Date histogram
- Purpose: "Is outbound volume increasing over time?"

## 9. Lateral Movement Candidates (Data Table)
- Query: `data.flow.direction:internal_to_internal AND data.destination.port:(445 OR 3389 OR 22 OR 5985)`
- Fields: data.source.ip, data.destination.ip, data.destination.port, data.network.bytes
- Purpose: "Which hosts are accessing admin services internally?"
