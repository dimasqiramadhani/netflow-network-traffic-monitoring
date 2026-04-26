#!/usr/bin/env bash
# install_netflow_tools.sh — Install NetFlow lab dependencies (Ubuntu)
# ⚠️ LAB USE ONLY

echo "============================================================"
echo " NetFlow Monitoring Lab — Dependency Installer"
echo " ⚠️  LAB USE ONLY — Ubuntu 22.04 / 24.04"
echo "============================================================"

sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv jq curl

# pmacct — required for direct interface packet capture (primary collector)
sudo apt install -y pmacct

# Create required directories
sudo mkdir -p /var/log/netflow /opt/netflow-wazuh
sudo chown "$USER":"$USER" /var/log/netflow /opt/netflow-wazuh
sudo chmod 755 /var/log/netflow

# Optional: nfdump (only needed if using nfcapd/softflowd pipeline instead of pmacctd)
read -rp "Install nfdump/softflowd (optional, not required for pmacctd pipeline)? [y/N]: " inst_nf
if [[ "$inst_nf" =~ ^[Yy]$ ]]; then
    sudo apt install -y nfdump softflowd
    sudo mkdir -p /var/cache/nfdump
    sudo chown "$USER":"$USER" /var/cache/nfdump
fi

echo "✅ Dependencies installed"
echo "   Next: start pmacctd — see README.md Setup Guide"
