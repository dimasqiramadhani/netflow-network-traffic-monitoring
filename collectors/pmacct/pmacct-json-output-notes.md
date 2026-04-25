# pmacct JSON Output Notes

## Run nfacctd

```bash
sudo nfacctd -f collectors/pmacct/nfacctd-sample.conf
```

## Validate JSON Output

```bash
tail -5 /var/log/netflow/pmacct-flows.json | python3 -m json.tool
```

## Connect to Normalizer

```bash
python3 scripts/normalize_netflow_to_wazuh.py \
    --pmacct /var/log/netflow/pmacct-flows.json \
    --output /var/log/netflow/netflow-wazuh.json
```

## pmacct JSON Field Reference

| pmacct Field | Normalized Field |
|-------------|-----------------|
| ip_src | source.ip |
| ip_dst | destination.ip |
| port_src | source.port |
| port_dst | destination.port |
| ip_proto | flow.protocol |
| bytes | network.bytes |
| packets | network.packets |
| timestamp_start | @timestamp |
| tcpflags | tcp.flags |
