#!/usr/bin/env bash
# rotate_netflow_logs.sh — Rotate NetFlow JSON log

[[ -f ".env" ]] && source ".env"

LOG_FILE="${NETFLOW_OUTPUT_LOG:-/var/log/netflow/netflow-wazuh.json}"
LOG_DIR="$(dirname "$LOG_FILE")"
KEEP_DAYS=7

echo "Rotating NetFlow logs in $LOG_DIR (keeping ${KEEP_DAYS} days)..."

# Compress yesterday's log if it exists as a rotated file
YESTERDAY="$(date -d 'yesterday' '+%Y-%m-%d')"
ROTATED="$LOG_DIR/netflow-wazuh-$YESTERDAY.json"

[[ -f "$ROTATED" ]] && gzip "$ROTATED" && echo "✅ Compressed: $ROTATED.gz"

# Remove logs older than KEEP_DAYS
find "$LOG_DIR" -name "netflow-wazuh-*.json.gz" -mtime +$KEEP_DAYS -delete
echo "✅ Removed compressed logs older than $KEEP_DAYS days"

# Copy current log to dated archive (non-destructive)
cp "$LOG_FILE" "$LOG_DIR/netflow-wazuh-$(date '+%Y-%m-%d').json" 2>/dev/null

# Truncate current log (Wazuh will resume from end — safe for inode tracking)
> "$LOG_FILE"
echo "✅ Current log truncated (Wazuh will resume from end)"
