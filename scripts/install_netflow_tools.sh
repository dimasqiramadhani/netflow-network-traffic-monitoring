#!/usr/bin/env bash
# install_netflow_tools.sh — Install NetFlow lab dependencies (Ubuntu)
# ⚠️ LAB USE ONLY

echo "============================================================"
echo " NetFlow Monitoring Lab — Dependency Installer"
echo " ⚠️  LAB USE ONLY — Ubuntu 22.04 / 24.04"
echo "============================================================"

sudo apt update -y
sudo apt install -y nfdump python3 python3-pip python3-venv jq curl

# Create directories
sudo mkdir -p /var/log/netflow /var/cache/nfdump /opt/netflow-wazuh
sudo chown "$USER":"$USER" /var/log/netflow /var/cache/nfdump /opt/netflow-wazuh

# Optional: pmacct
read -rp "Install pmacct? [y/N]: " inst_pmacct
[[ "$inst_pmacct" =~ ^[Yy]$ ]] && sudo apt install -y pmacct

# Optional: softflowd
read -rp "Install softflowd? [y/N]: " inst_soft
[[ "$inst_soft" =~ ^[Yy]$ ]] && sudo apt install -y softflowd

echo "✅ Dependencies installed"
echo "   Next: bash scripts/start_nfcapd_collector.sh"
