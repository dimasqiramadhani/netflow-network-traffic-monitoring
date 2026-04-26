#!/usr/bin/env bash
# rotate_netflow_logs.sh — Archive NetFlow raw logs
# Project: Network Flow Monitoring and Anomaly Detection with Wazuh
# Author:  Dimas Qi Ramadhani
#
# CATATAN: Script ini untuk mengarsipkan netflow-raw.json (output pmacctd)
# yang terus-menerus di-overwrite oleh pmacctd setiap 60 detik.
#
# netflow-wazuh.json (output normalizer) TIDAK perlu di-rotate karena
# normalizer sudah overwrite file itu setiap menit via cron.
#
# Jalankan script ini via cron harian jika ingin menyimpan arsip raw flows:
# 0 0 * * * bash /path/to/rotate_netflow_logs.sh

[[ -f ".env" ]] && source ".env"

RAW_FILE="${NETFLOW_RAW_OUTPUT:-/var/log/netflow/netflow-raw.json}"
LOG_DIR="$(dirname "$RAW_FILE")"
KEEP_DAYS=7
ARCHIVE_DIR="$LOG_DIR/archive"

mkdir -p "$ARCHIVE_DIR"

# Archive current raw file dengan timestamp
ARCHIVE_NAME="netflow-raw-$(date '+%Y-%m-%d-%H%M').json"
if [[ -f "$RAW_FILE" && -s "$RAW_FILE" ]]; then
    cp "$RAW_FILE" "$ARCHIVE_DIR/$ARCHIVE_NAME"
    gzip "$ARCHIVE_DIR/$ARCHIVE_NAME"
    echo "✅ Archived: $ARCHIVE_DIR/$ARCHIVE_NAME.gz"
else
    echo "[INFO] Raw file kosong atau tidak ada, skip archiving"
fi

# Hapus arsip lebih dari KEEP_DAYS hari
find "$ARCHIVE_DIR" -name "netflow-raw-*.json.gz" -mtime "+$KEEP_DAYS" -delete
echo "✅ Removed archives older than $KEEP_DAYS days"
