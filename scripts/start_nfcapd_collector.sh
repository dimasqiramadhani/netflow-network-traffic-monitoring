#!/usr/bin/env bash
# start_nfcapd_collector.sh — Start nfcapd NetFlow collector
# ⚠️ Bind to lab interface only. Never expose UDP 2055 to internet.

[[ -f ".env" ]] && source ".env"

COLLECTOR_PORT="${NETFLOW_COLLECTOR_PORT:-2055}"
FLOW_DIR="${NETFLOW_INPUT_DIR:-/var/cache/nfdump}"

mkdir -p "$FLOW_DIR"

# Check if port is already in use
if ss -ulnp | grep -q ":$COLLECTOR_PORT"; then
    echo "⚠️  UDP port $COLLECTOR_PORT already in use"
    ss -ulnp | grep ":$COLLECTOR_PORT"
    exit 1
fi

echo "Starting nfcapd on UDP :$COLLECTOR_PORT → $FLOW_DIR"
sudo nfcapd -D -l "$FLOW_DIR" -p "$COLLECTOR_PORT" -S 1

echo "✅ nfcapd started"
echo "   Check: sudo ss -ulnp | grep $COLLECTOR_PORT"
echo "   Firewall: sudo ufw allow from <exporter-ip> to any port $COLLECTOR_PORT proto udp"
