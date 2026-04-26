#!/usr/bin/env bash
# pmacct-collector.sh — Start pmacctd for direct interface packet capture
# Project: Network Flow Monitoring and Anomaly Detection with Wazuh
# Author:  Dimas Qi Ramadhani
# ⚠️  LAB USE ONLY

[[ -f ".env" ]] && source ".env"

INTERFACE="${NETFLOW_INTERFACE:-enp1s0}"
OUTPUT_FILE="${NETFLOW_RAW_OUTPUT:-/var/log/netflow/netflow-raw.json}"
FLUSH_INTERVAL="${NETFLOW_FLUSH_INTERVAL:-60}"

# Auto-detect interface if the configured one is not found
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "⚠️  Interface $INTERFACE not found. Detecting..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    echo "   Using: $INTERFACE"
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

echo "Starting pmacctd on interface: $INTERFACE"
echo "Output: $OUTPUT_FILE (flush every ${FLUSH_INTERVAL}s)"

sudo pmacctd \
    -i "$INTERFACE" \
    -c src_host,dst_host,src_port,dst_port,proto \
    -P print \
    -O json \
    -o "$OUTPUT_FILE" \
    -r "$FLUSH_INTERVAL" \
    -D

echo "✅ pmacctd started"
echo "   Verify: ps aux | grep pmacctd"
echo "   Wait ${FLUSH_INTERVAL}s then check: cat $OUTPUT_FILE | head -3"
echo ""
echo "   Next: run the normalizer"
echo "   python3 scripts/normalize_netflow_to_wazuh.py \\"
echo "     --pmacct $OUTPUT_FILE \\"
echo "     --output /var/log/netflow/netflow-wazuh.json"
