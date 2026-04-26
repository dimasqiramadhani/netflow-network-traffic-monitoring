# 15 — Incident Investigation Playbook

## NetFlow Alert Triage

### Step 1: Confirm Alert
- rule.id, rule.level, rule.description
- anomaly.tags — what type of anomaly?
- source.ip, destination.ip, destination.port

### Step 2: Determine Flow Direction
- `internal_to_internal` → lateral movement risk
- `internal_to_external` → exfiltration risk
- `external_to_internal` → inbound attack/access risk

### Step 3: Review Flow Metadata
- `network.bytes` — how much data?
- `network.packets` — packet count
- `event.duration` — how long?
- `flow.protocol` — TCP/UDP/ICMP?
- `service.name` — what service?

### Step 4: Compare Against Baseline
- Is this source IP normally active?
- Is this destination normal for this host?
- Is this volume normal for this time of day?

### Step 5: Correlate with Other Logs

| Flow Anomaly | Correlate With |
|-------------|---------------|
| Port scan | Firewall deny logs, Wazuh/EDR on target |
| High outbound | Proxy logs, DNS logs, DLP logs |
| Beaconing | Endpoint process tree, DNS query logs |
| Lateral movement | Windows Security Event 4624/4625, Sysmon |
| High DNS volume | DNS resolver logs, query names |

### Step 6: Response Decision

| Confidence | Finding | Action |
|-----------|---------|--------|
| High | Confirmed C2 beaconing | Isolate host, block destination |
| High | Data exfiltration confirmed | Incident response activation |
| Medium | Suspected lateral movement | Investigate auth logs, alert owner |
| Low | Authorized scanner detected | Tune rule, add to allowlist |
| Low | Backup job (high bytes) | Add to exception list |

### Step 7: Document Evidence

```bash
bash scripts/collect_netflow_evidence.sh
```

### Step 8: Tune Rules

- If false positive: adjust threshold or add source IP exception
- If detection gap: lower threshold or add new anomaly tag
- Document all tuning decisions
