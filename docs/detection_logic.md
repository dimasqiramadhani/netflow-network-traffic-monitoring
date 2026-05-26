# Detection Logic

This document explains the custom Wazuh decoder and rules used to detect network flow anomalies.

## Custom Decoder

File: `rules/decoders/netflow_decoder.xml`

The decoder extracts fields from the normalized JSON log events. Since the Wazuh Agent is configured with `log_format: json`, the JSON fields are automatically available as dynamic fields. The decoder provides additional structure and field naming for rule evaluation.

**Decoder logic:**

1. The parent decoder (`netflow_json`) matches any event containing the `netflow.src_ip` field — this identifies the event as a NetFlow record.
2. The child decoder (`netflow_json_fields`) extracts specific fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, and `packets`.

**Decoded fields available to rules:**

| Decoded Field | Source JSON Path | Description |
|---|---|---|
| netflow.src_ip | netflow.src_ip | Source IP address |
| netflow.dst_ip | netflow.dst_ip | Destination IP address |
| netflow.src_port | netflow.src_port | Source port |
| netflow.dst_port | netflow.dst_port | Destination port |
| netflow.protocol | netflow.protocol | Transport protocol (tcp, udp, icmp) |
| netflow.bytes | netflow.bytes | Total bytes transferred |
| netflow.packets | netflow.packets | Total packets in flow |

## Custom Rules

File: `rules/rules/netflow_rules.xml`

### Rule 117001 — NetFlow Event Received (Base Rule)

```xml
<rule id="117001" level="3">
  <decoded_as>netflow_json</decoded_as>
  <description>NetFlow: Network flow event received</description>
  <group>netflow,</group>
</rule>
```

**Purpose:** Base rule that matches any decoded NetFlow event. All other NetFlow rules depend on this rule using `if_sid`. Level 3 keeps it as a low-severity informational alert.

### Rule 117002 — High Connection Volume

```xml
<rule id="117002" level="8" frequency="20" timeframe="60">
  <if_matched_sid>117001</if_matched_sid>
  <same_field>netflow.src_ip</same_field>
  <description>NetFlow: High connection volume from $(netflow.src_ip)</description>
  <group>netflow,network_anomaly,</group>
</rule>
```

**Purpose:** Fires when the same source IP generates more than 20 flow events within 60 seconds. This can indicate port scanning, network sweeping, or an application generating excessive outbound connections.

**Detection logic:** Uses Wazuh's frequency-based rule matching. The `same_field` option groups events by source IP before counting.

### Rule 117003 — Suspicious External Destination

```xml
<rule id="117003" level="10" frequency="5" timeframe="120">
  <if_sid>117001</if_sid>
  <field name="netflow.dst_ip">!^192\.168\.|!^10\.|!^172\.(1[6-9]|2[0-9]|3[01])\.</field>
  <description>NetFlow: Suspicious external destination detected - $(netflow.dst_ip)</description>
  <group>netflow,network_threat,</group>
</rule>
```

**Purpose:** Triggers when an internal host communicates with a non-RFC1918 external IP address and the activity occurs at least 5 times within 120 seconds. This catches potential command-and-control communication, data exfiltration, or connections to unknown external infrastructure.

**Note:** In a production environment, this rule should be paired with a CDB list of known-good external IPs to reduce false positives.

### Rule 117004 — Repeated Connection Activity

```xml
<rule id="117004" level="6" frequency="10" timeframe="120">
  <if_matched_sid>117001</if_matched_sid>
  <same_field>netflow.dst_ip</same_field>
  <description>NetFlow: Repeated connection activity to $(netflow.dst_ip)</description>
  <group>netflow,network_anomaly,</group>
</rule>
```

**Purpose:** Fires when 10 or more flow events target the same destination IP within 120 seconds. This can indicate beaconing behavior, persistent connections to a suspicious host, or automated communication patterns.

### Rule 117005 — Unusual Destination Port

```xml
<rule id="117005" level="7">
  <if_sid>117001</if_sid>
  <field name="netflow.dst_port">^(4444|5555|6666|7777|8888|9999|1337|31337)$</field>
  <description>NetFlow: Unusual destination port $(netflow.dst_port) detected</description>
  <group>netflow,network_anomaly,</group>
</rule>
```

**Purpose:** Matches flow events where the destination port is commonly associated with backdoors, reverse shells, or offensive tooling. The port list is intentionally short for this PoC — in production, it would be expanded based on threat intelligence and environment-specific baselines.

**Ports flagged:**
- 4444 — Common Metasploit/Meterpreter listener
- 5555 — Android Debug Bridge, some backdoors
- 6666 — IRC-based C2
- 7777, 8888, 9999 — Non-standard ports often used in testing and adversary tooling
- 1337, 31337 — Classic "leet" ports associated with legacy backdoors

## Rule Dependency Chain

```
117001 (Base: NetFlow event received)
  ├── 117002 (Frequency: High volume from same source)
  ├── 117003 (Field match: External destination + frequency)
  ├── 117004 (Frequency: Repeated connections to same destination)
  └── 117005 (Field match: Suspicious destination port)
```

All detection rules depend on rule 117001. If the base rule does not match (because the decoder failed or the event format is wrong), none of the child rules will fire.

## Testing Rules

Use `wazuh-logtest` on VM 1 to test the decoder and rules:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a normalized JSON line:

```
{"timestamp":"2025-01-15T10:32:01Z","netflow":{"src_ip":"192.168.10.15","dst_ip":"185.220.101.34","src_port":49832,"dst_port":4444,"protocol":"tcp","packets":12,"bytes":3456,"duration_sec":29}}
```

Expected output should show:
1. The decoder matching as `netflow_json`.
2. Rule 117001 firing (base rule).
3. Rule 117005 firing (unusual port 4444).
