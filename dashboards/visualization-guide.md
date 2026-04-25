# Wazuh Dashboard — NetFlow Visualization Guide

## 1. Top Source IPs (Pie or Data Table)
- Query: `rule.groups:netflow`
- Bucket: Terms on `data.source.ip`
- Metric: Count
- Size: 10
- Purpose: "Who is generating the most network activity?"

## 2. Top Destination IPs by Bytes (Data Table)
- Query: `rule.groups:netflow`  
- Metric: Sum of `data.network.bytes`
- Bucket: Terms on `data.destination.ip`
- Purpose: "Which destinations receive the most data?"

## 3. Flow Direction Distribution (Pie)
- Bucket: Terms on `data.flow.direction`
- Purpose: "What ratio of east-west vs. north-south traffic?"

## 4. Destination Port Distribution (Bar)
- Bucket: Terms on `data.destination.port`
- Purpose: "Which services are being accessed?"

## 5. NetFlow Anomaly Timeline (Line)
- Query: `rule.groups:network_anomaly`
- X-axis: Date histogram
- Purpose: "When are anomalies happening?"

## 6. High Outbound Bytes Over Time (Line)
- Query: `rule.id:117002`
- Y-axis: Sum of `data.network.bytes`
- Purpose: "Is outbound volume increasing?"

## 7. Lateral Movement Candidates (Data Table)
- Query: `data.flow.direction:internal_to_internal AND data.destination.port:(445 OR 3389 OR 22 OR 5985)`
- Fields: source.ip, destination.ip, destination.port, network.bytes
- Purpose: "Which hosts are accessing admin services internally?"
