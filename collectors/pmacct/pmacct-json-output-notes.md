# pmacct JSON Output Notes

## Cara Menjalankan pmacctd (Direct Interface Capture)

pmacctd melakukan packet capture langsung dari network interface — tidak memerlukan
NetFlow exporter (softflowd/router). Ini yang digunakan di lab ini.

```bash
# Cek nama interface dulu
ip a

# Jalankan pmacctd (ganti enp1s0 dengan interface lo)
sudo pmacctd -i enp1s0 \
  -c src_host,dst_host,src_port,dst_port,proto \
  -P print -O json \
  -o /var/log/netflow/netflow-raw.json \
  -r 60 -D

# Atau gunakan script yang sudah tersedia
bash collectors/pmacct/pmacct-collector.sh
```

Tunggu 60 detik, lalu verifikasi output:

```bash
cat /var/log/netflow/netflow-raw.json | head -3
```

## Format Output pmacctd

pmacctd dengan flag `-c src_host,dst_host,src_port,dst_port,proto` menghasilkan:

```json
{"event_type": "purge", "ip_src": "160.22.251.111", "ip_dst": "8.8.8.8", "port_src": 0, "port_dst": 0, "ip_proto": "icmp", "packets": 10, "bytes": 840}
{"event_type": "purge", "ip_src": "192.109.200.50", "ip_dst": "160.22.251.111", "port_src": 47156, "port_dst": 22, "ip_proto": "tcp", "packets": 13, "bytes": 2100}
```

> **Penting:** `ip_proto` di-output sebagai **string nama protokol** (`"tcp"`, `"udp"`, `"icmp"`, `"igmp"`),
> bukan angka. Normalizer versi terbaru sudah handle kedua format.

## Field Reference (output pmacctd di lab ini)

| pmacctd Field | Isi | Normalized Field |
|--------------|-----|-----------------|
| `ip_src` | Source IP address | `source.ip` |
| `ip_dst` | Destination IP address | `destination.ip` |
| `port_src` | Source port | `source.port` |
| `port_dst` | Destination port | `destination.port` |
| `ip_proto` | Protocol name string (`"tcp"`, `"udp"`, dll) | `flow.protocol` |
| `packets` | Packet count | `network.packets` |
| `bytes` | Bytes transferred | `network.bytes` |
| `event_type` | Selalu `"purge"` (flush event) | — (tidak di-map) |

## Jalankan Normalizer

```bash
python3 scripts/normalize_netflow_to_wazuh.py \
    --pmacct /var/log/netflow/netflow-raw.json \
    --output /var/log/netflow/netflow-wazuh.json
```

Atau otomatis via cron:

```bash
bash scripts/setup_cron.sh
```
