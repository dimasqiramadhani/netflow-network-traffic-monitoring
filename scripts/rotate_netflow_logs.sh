#!/usr/bin/env bash
# rotate_netflow_logs.sh — Archive NetFlow raw logs
# Project: Network Flow Monitoring and Anomaly Detection with Wazuh
# Author:  Dimas Qi Ramadhani
#
# NOTE: This script archives netflow-raw.json (pmacctd output)
# which is continuously overwritten by pmacctd every 60 seconds.
#
# netflow-wazuh.json (normalizer output) does NOT need rotation because
# the normalizer already overwrites it every minute via cron.
#
# Run this script via daily cron to retain raw flow archives:
# 0 0 * * * bash /path/to/rotate_netflow_logs.sh

[[ -f ".env" ]] && source ".env"

RAW_FILE="${NETFLOW_RAW_OUTPUT:-/var/log/netflow/netflow-raw.json}"
LOG_DIR="$(dirname "$RAW_FILE")"
KEEP_DAYS=7
ARCHIVE_DIR="$LOG_DIR/archive"

mkdir -p "$ARCHIVE_DIR"

# Archive current raw file with timestamp
ARCHIVE_NAME="netflow-raw-$(date '+%Y-%m-%d-%H%M').json"
if [[ -f "$RAW_FILE" && -s "$RAW_FILE" ]]; then
    cp "$RAW_FILE" "$ARCHIVE_DIR/$ARCHIVE_NAME"
    gzip "$ARCHIVE_DIR/$ARCHIVE_NAME"
    echo "✅ Archived: $ARCHIVE_DIR/$ARCHIVE_NAME.gz"
else
    echo "[INFO] Raw file is empty or missing, skipping archive"
fi

# Remove archives older than KEEP_DAYS
find "$ARCHIVE_DIR" -name "netflow-raw-*.json.gz" -mtime "+$KEEP_DAYS" -delete
echo "✅ Removed archives older than $KEEP_DAYS days"
