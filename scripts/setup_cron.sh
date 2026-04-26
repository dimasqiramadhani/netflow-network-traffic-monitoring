#!/usr/bin/env bash
# setup_cron.sh — Setup cron job to run normalizer every minute
# Project: Network Flow Monitoring and Anomaly Detection with Wazuh
# Author:  Dimas Qi Ramadhani

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NORMALIZER="$PROJECT_DIR/scripts/normalize_netflow_to_wazuh.py"
RAW_INPUT="${NETFLOW_RAW_OUTPUT:-/var/log/netflow/netflow-raw.json}"
WAZUH_OUTPUT="/var/log/netflow/netflow-wazuh.json"

CRON_LINE="* * * * * rm -f $WAZUH_OUTPUT && python3 $NORMALIZER --pmacct $RAW_INPUT --output $WAZUH_OUTPUT"

# Check if already exists
if sudo crontab -l 2>/dev/null | grep -qF "$NORMALIZER"; then
    echo "⚠️  Cron entry already exists. No changes made."
    echo "   Current crontab:"
    sudo crontab -l | grep netflow
    exit 0
fi

# Add to crontab
(sudo crontab -l 2>/dev/null; echo "$CRON_LINE") | sudo crontab -

echo "✅ Cron job added"
echo "   Runs every minute: normalizer → $WAZUH_OUTPUT"
echo "   Verify: sudo crontab -l | grep netflow"
echo "   Wait 2 minutes then check: ls -la $WAZUH_OUTPUT"
