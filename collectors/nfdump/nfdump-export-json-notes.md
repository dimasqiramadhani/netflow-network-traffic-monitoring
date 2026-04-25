# nfdump Flow Export Notes

## Read Flow File

```bash
nfdump -r /var/cache/nfdump/nfcapd.YYYYMMDDHHMMSS -o long | head -20
```

## Field Order in nfdump Long Format

```
Date first seen  Duration  Proto  Src IP:Port  ->  Dst IP:Port  Flags  Packets  Bytes  Flows
```

## Key Fields to Map

| nfdump Field | Normalized Field |
|-------------|-----------------|
| Date first seen | @timestamp |
| Duration | event.duration |
| Proto | flow.protocol |
| Src IP | source.ip |
| Src Port | source.port |
| Dst IP | destination.ip |
| Dst Port | destination.port |
| Packets | network.packets |
| Bytes | network.bytes |
| Flags | tcp.flags |

## Pipe to Normalizer

```bash
nfdump -r /var/cache/nfdump/nfcapd.* -o long | \
    python3 scripts/normalize_netflow_to_wazuh.py --output /var/log/netflow/netflow-wazuh.json
```

## Note on Format Variations

nfdump output format may vary between versions. If the normalizer fails to parse, run `nfdump -r <file> -o long | head -5` to inspect the actual format and adjust the regex in `normalize_netflow_to_wazuh.py`.
