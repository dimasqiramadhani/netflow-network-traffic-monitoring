# 17 — Troubleshooting

## Collector Not Receiving Flows

```bash
# Check UDP port is listening
ss -ulnp | grep 2055

# Check firewall
sudo ufw status | grep 2055
# or
sudo iptables -L -n | grep 2055

# Test with netcat from exporter host
echo "test" | nc -u <collector-ip> 2055
```

## nfcapd Not Creating Files

```bash
# Check nfcapd is running
ps aux | grep nfcapd

# Verify directory exists and is writable
ls -la /var/cache/nfdump/

# Run nfcapd in foreground verbose mode
sudo nfcapd -D -l /var/cache/nfdump/ -p 2055 -v
```

## nfdump Not Reading Flow Files

```bash
# List files in flow directory
ls -la /var/cache/nfdump/

# Check file format
nfdump -r /var/cache/nfdump/<file> -c 10
```

## pmacct JSON Output Empty

```bash
# Check nfacctd process
ps aux | grep nfacctd

# Check output file
tail -20 /var/log/netflow/pmacct-flows.json

# Check nfacctd logs for errors
journalctl -u nfacctd --since "1 hour ago"
```

## Normalizer Failing

```bash
# Test normalizer manually
python3 scripts/normalize_netflow_to_wazuh.py < samples/sample-nfdump-output.txt | head -5 | python3 -m json.tool
```

## Wazuh Agent Not Reading Log File

```bash
# Verify file exists and has content
ls -la /var/log/netflow/netflow-wazuh.json
tail -5 /var/log/netflow/netflow-wazuh.json | python3 -m json.tool

# Check permissions (Wazuh agent runs as wazuh)
sudo chmod 644 /var/log/netflow/netflow-wazuh.json
```

## Custom Decoder Not Matching

```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a normalized flow event
# Expect: Phase 2 decoder = netflow-json

# Also validate XML
xmllint --noout /var/ossec/etc/decoders/netflow_decoders.xml
```

## Flow Direction Incorrect

Check `INTERNAL_NETWORKS` in your `.env` — if the internal network definition is wrong, all flows will show incorrect direction. Example:

```
# If lab is 192.168.56.0/24 but you set 10.0.0.0/8:
INTERNAL_NETWORKS=192.168.56.0/24,10.10.10.0/24
```

## Too Many Alerts / Too Noisy

- Increase `PORTSCAN_UNIQUE_PORT_THRESHOLD` for port scan rule (default: 20)
- Increase `EXTERNAL_TRAFFIC_THRESHOLD_BYTES` for high outbound rule
- Add known scanner IPs to an allowlist in the normalizer
- Reduce rule level from 9 to 6 for frequent FP rules

## Timezone Mismatch

Ensure collector host, exporter, and Wazuh all use UTC or the same timezone. Check:

```bash
timedatectl
date -u
```

---

## Wazuh Manager Gagal Start Setelah Deploy Decoder

**Gejala:**
```
wazuh-analysisd: ERROR: Invalid decoder type 'json'
wazuh-analysisd: CRITICAL: (1202): Configuration error at 'etc/decoders/netflow_decoders.xml'
```

**Penyebab:** `<type>json</type>` tidak valid di Wazuh v4.x.

**Fix:** Pastikan menggunakan `netflow_decoders.xml` versi terbaru — tag `<type>json</type>` sudah dihapus. JSON parsing di-handle oleh `log_format: json` di ossec.conf agent, bukan di decoder.

```bash
# Verifikasi decoder tidak ada type tag
grep "type" /var/ossec/etc/decoders/netflow_decoders.xml
# Seharusnya tidak ada output

sudo systemctl restart wazuh-manager
```

---

## Alert Muncul Tapi rule.id Hanya 117010, Tidak Ada 117001-117008

**Gejala:** Event netflow masuk ke dashboard tapi hanya rule 117010 (base visibility) yang fired.

**Penyebab:** Rules 117001-117008 menggunakan field `data.anomaly.tags`, `data.flow.direction`, dll. Tapi dengan `log_format: json`, field aktual adalah tanpa prefix `data.` — yaitu `anomaly.tags`, `flow.direction`, dll.

**Fix:** Pastikan menggunakan `netflow_rules.xml` versi terbaru yang sudah menghapus prefix `data.` dari semua field name.

```bash
# Verifikasi rules tidak ada data. prefix
grep "data\." /var/ossec/etc/rules/netflow_rules.xml
# Seharusnya tidak ada output

sudo systemctl restart wazuh-manager

# Test dengan wazuh-logtest
sudo /var/ossec/bin/wazuh-logtest
# Paste event dengan anomaly.tags berisi possible_port_scan
# Phase 3 harus menampilkan rule id: '117001'
```

---

## field flow.protocol Berisi PROTOtcp Bukan TCP

**Gejala:** Di Wazuh Dashboard, field `flow.protocol` menampilkan `PROTOtcp`, `PROTOudp`, dll.

**Penyebab:** pmacctd output `ip_proto` sebagai string nama protokol (`"tcp"`, `"udp"`, `"igmp"`), bukan angka (`"6"`, `"17"`). Normalizer versi lama hanya handle angka.

**Fix:** Pastikan menggunakan `normalize_netflow_to_wazuh.py` versi terbaru yang sudah handle kedua format.

```bash
# Test normalizer
echo '{"ip_src":"1.1.1.1","ip_dst":"2.2.2.2","port_src":1234,"port_dst":443,"ip_proto":"tcp","packets":1,"bytes":100}' \
  > /tmp/test-pmacct.json

python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /tmp/test-pmacct.json \
  --output /tmp/test-out.json

cat /tmp/test-out.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['flow.protocol'])"
# Harus output: TCP
```

---

## softflowd / nfcapd: "No matched flows"

**Gejala:** nfcapd jalan, softflowd jalan, tapi `nfdump -R /var/cache/nfdump/` selalu "No matched flows".

**Penyebab:** Di cloud VM environment (OpenStack, AWS, GCP, dll), traffic diproses di level hypervisor sebelum sampai ke interface. softflowd menggunakan libpcap yang tidak bisa capture byte/packet counters dengan benar — hasilnya flow records kosong.

**Fix:** Gunakan pmacctd sebagai collector, bukan nfcapd/softflowd:

```bash
sudo pkill nfcapd
sudo pkill softflowd

# Cek nama interface
ip a

# Jalankan pmacctd langsung dari interface
sudo pmacctd -i enp1s0 \
  -c src_host,dst_host,src_port,dst_port,proto \
  -P print -O json \
  -o /var/log/netflow/netflow-raw.json \
  -r 60 -D

# Tunggu 65 detik, verifikasi
cat /var/log/netflow/netflow-raw.json | head -3
```

Atau gunakan script yang sudah tersedia:
```bash
bash collectors/pmacct/pmacct-collector.sh
```

---

## Localfile Duplikat di ossec.conf

**Gejala:**
```
WARNING: (1958): Log file '/var/log/netflow/netflow-wazuh.json' is duplicated.
```

**Penyebab:** Entry localfile netflow ditambahkan dua kali ke ossec.conf (bisa terjadi jika menjalankan penambahan config lebih dari sekali).

**Fix:**
```bash
# Cek duplikat
grep -n "netflow" /var/ossec/etc/ossec.conf

# Edit manual, hapus salah satu blok
sudo nano /var/ossec/etc/ossec.conf

# Pastikan hanya satu entry
grep -c "netflow-wazuh.json" /var/ossec/etc/ossec.conf
# Harus output: 1

sudo systemctl restart wazuh-agent
```

---

## Custom Decoder Tidak Match (Phase 2 menampilkan name: 'json' bukan 'netflow-json')

**Ini normal dan expected.** Dengan `log_format: json` di localfile, Wazuh menggunakan built-in json decoder secara otomatis. Custom decoder `netflow-json` hanya digunakan sebagai anchor untuk rule 117000 (`<decoded_as>json</decoded_as>`). Yang penting di wazuh-logtest adalah Phase 3 menampilkan rule yang benar, bukan nama decoder-nya.

---

## wazuh-logtest: Input yang Benar

**Gejala:** wazuh-logtest tidak match decoder / Phase 3 tidak muncul padahal rules sudah benar.

**Penyebab:** Input yang di-paste bukan format yang benar. wazuh-logtest menerima **satu baris raw JSON event** (output normalizer), bukan format Wazuh alert JSON.

**Input yang SALAH** (ini format Wazuh alert, bukan input logtest):
```json
{
  "rule": {"id": "117001"},
  "data": {"source.ip": "..."},
  ...
}
```

**Input yang BENAR** (satu baris output normalizer):
```bash
# Generate dulu dengan:
python3 scripts/generate_safe_netflow_test_events.py --scenario port_scan --count 1

# Output-nya yang di-paste ke wazuh-logtest, contoh:
{"@timestamp": "2026-04-26T11:45:20Z", "source": "netflow", "collector.name": "lab-collector-01", "exporter.ip": "192.168.56.1", "flow.protocol": "TCP", "source.ip": "192.168.56.30", "source.port": "48739", "destination.ip": "192.168.56.28", "destination.port": "47775", "network.bytes": 60, "network.packets": 1, "event.duration": 0.001, "tcp.flags": "SYN", "flow.direction": "internal_to_internal", "internal.src": true, "internal.dst": true, "service.name": "OTHER", "event.type": "network", "event.category": "network_traffic", "anomaly.tags": ["possible_port_scan"]}
```

---

## Testing: generate_safe_netflow_test_events.py Tidak Menghasilkan Alert

**Gejala:** Generate test events berhasil tapi tidak ada alert 117001-117005 di dashboard.

**Penyebab paling umum:** Cron normalizer masih aktif dan overwrite file setiap menit sebelum Wazuh Agent sempat membaca seluruh events.

**Fix:**
```bash
# 1. Pause cron dulu
sudo crontab -e  # tambahkan # di depan baris normalizer

# 2. Generate test events
python3 scripts/generate_safe_netflow_test_events.py \
  --scenario all \
  --output /var/log/netflow/netflow-wazuh.json

# 3. Tunggu 30 detik untuk Wazuh Agent pickup

# 4. Verifikasi alert di VM 1
sudo grep -E '"id":"11700[1-9]"' /var/ossec/logs/alerts/alerts.json | tail -5

# 5. Aktifkan kembali cron setelah testing
sudo crontab -e  # hapus tanda #
```

---

## source.ip / destination.ip Tidak Muncul di Wazuh Dashboard

**Gejala:** Di Wazuh Dashboard, field `source.ip` tidak muncul atau kosong meskipun event masuk.

**Penyebab:** Format JSON lama menggunakan flat dot-notation key seperti `"source.ip": "x.x.x.x"`. Wazuh JSON_Decoder memperlakukan titik sebagai pemisah nested object. Karena `"source"` juga dipakai sebagai string `"netflow"`, terjadi konflik — Wazuh tidak bisa decode `source` sebagai string sekaligus sebagai parent object dari `.ip`.

**Fix:** Normalizer versi terbaru sudah menggunakan nested JSON:

```json
{
  "source": {"ip": "192.168.56.10", "port": "52341"},
  "destination": {"ip": "8.8.8.8", "port": "443"},
  "flow": {"protocol": "TCP", "direction": "internal_to_external"}
}
```

Dengan struktur ini, field di Wazuh Dashboard muncul sebagai:
- `data.source.ip` → IP sumber
- `data.destination.ip` → IP tujuan
- `data.flow.protocol` → protokol
- `data.anomaly.tags` → anomaly tags

Pastikan menggunakan `normalize_netflow_to_wazuh.py` versi terbaru, lalu regenerate `netflow-wazuh.json`:

```bash
rm -f /var/log/netflow/netflow-wazuh.json
python3 scripts/normalize_netflow_to_wazuh.py \
  --pmacct /var/log/netflow/netflow-raw.json \
  --output /var/log/netflow/netflow-wazuh.json

# Verifikasi format nested
head -1 /var/log/netflow/netflow-wazuh.json | python3 -m json.tool | grep -A2 '"source"'
# Harus output:
# "source": {
#     "ip": "x.x.x.x",
```
