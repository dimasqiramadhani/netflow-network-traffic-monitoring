#!/usr/bin/env bash
# export_nfdump_to_json.sh — Export latest nfdump flows, normalize, write to Wazuh log

[[ -f ".env" ]] && source ".env"

FLOW_DIR="${NETFLOW_INPUT_DIR:-/var/cache/nfdump}"
OUTPUT_LOG="${NETFLOW_OUTPUT_LOG:-/var/log/netflow/netflow-wazuh.json}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find most recently modified flow file
LATEST=$(find "$FLOW_DIR" -name "nfcapd.*" -newer "${FLOW_DIR}/.last_export" 2>/dev/null | head -1)

[[ -z "$LATEST" ]] && {
    echo "[INFO] No new flow files to process since last export"
    exit 0
}

echo "[INFO] Processing: $LATEST"

# Export nfdump in long format, pipe to normalizer, then to anomaly detector
nfdump -r "$LATEST" -o long 2>/dev/null \
    | python3 "$SCRIPT_DIR/normalize_netflow_to_wazuh.py" 2>/dev/null \
    | python3 "$SCRIPT_DIR/detect_flow_anomalies.py" --output "$OUTPUT_LOG"

touch "${FLOW_DIR}/.last_export"
echo "[INFO] Output appended: $OUTPUT_LOG"
