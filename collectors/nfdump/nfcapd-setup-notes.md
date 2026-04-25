# nfcapd Setup Notes — NetFlow Collector

## Install nfdump

```bash
sudo apt install -y nfdump
nfdump --version
```

## Create Flow Directory

```bash
sudo mkdir -p /var/cache/nfdump
sudo chown "$USER":"$USER" /var/cache/nfdump
```

## Start nfcapd Collector

```bash
# Listen on UDP 2055, save files to /var/cache/nfdump, rotate every 5 minutes
sudo nfcapd -D -l /var/cache/nfdump -p 2055 -S 1

# Verify listening
sudo ss -ulnp | grep 2055
```

## Validate Flow Files Created

```bash
ls -lh /var/cache/nfdump/
# Expected: nfcapd.YYYYMMDDHHMMSS files appearing after traffic arrives
```

## Security Notes

- **Never expose UDP 2055 to the internet** — no authentication on NetFlow
- Restrict with firewall:
  ```bash
  sudo ufw allow from <exporter-lab-ip> to any port 2055 proto udp
  ```
- For lab: bind to lab interface only using `-B <bind-ip>` flag
