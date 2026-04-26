#!/usr/bin/env bash
# collect_netflow_evidence.sh — READ-ONLY evidence collection

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
mkdir -p evidence
OUTPUT="evidence/netflow-evidence-${TIMESTAMP}.txt"

collect() {
    echo "============================================================" >> "$OUTPUT"
    echo "$1" >> "$OUTPUT"
    echo "------------------------------------------------------------" >> "$OUTPUT"
    eval "$2" >> "$OUTPUT" 2>&1
    echo "" >> "$OUTPUT"
}

{ echo "NetFlow Monitoring Evidence"; echo "Generated: $(date)"; echo "Host: $(hostname)"; } > "$OUTPUT"
echo "" >> "$OUTPUT"

collect "OS VERSION"              "hostnamectl"
collect "WAZUH AGENT"             "systemctl status wazuh-agent --no-pager | head -10"
collect "PMACCTD PROCESS"          "ps aux | grep pmacctd | grep -v grep"
collect "CRON NORMALIZER"         "sudo crontab -l 2>/dev/null | grep netflow"
collect "NETFLOW RAW FILE"        "ls -lh /var/log/netflow/netflow-raw.json 2>/dev/null && tail -3 /var/log/netflow/netflow-raw.json 2>/dev/null"
collect "LATEST FLOW EVENTS (50)" "tail -50 ${NETFLOW_OUTPUT_LOG:-/var/log/netflow/netflow-wazuh.json} 2>/dev/null"
collect "NETFLOW LOG SIZE"        "du -sh ${NETFLOW_OUTPUT_LOG:-/var/log/netflow/netflow-wazuh.json} 2>/dev/null"
collect "WAZUH AGENT LOG"         "tail -20 /var/ossec/logs/ossec.log 2>/dev/null"
collect "CUSTOM RULES DEPLOYED"   "ls -la /var/ossec/etc/rules/netflow_rules.xml 2>/dev/null"
collect "CUSTOM DECODER DEPLOYED" "ls -la /var/ossec/etc/decoders/netflow_decoders.xml 2>/dev/null"

echo "Evidence saved: $OUTPUT"
echo "⚠️  Review and redact IP addresses if needed before sharing."
