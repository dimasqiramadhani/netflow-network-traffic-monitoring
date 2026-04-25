# softflowd Exporter Notes — Lab NetFlow Export from Linux Host

## Purpose

If your lab has no physical router or firewall that exports NetFlow, use
**softflowd** on a Linux host to generate NetFlow records from observed
traffic on a network interface.

## Install

```bash
sudo apt install -y softflowd
```

## Start softflowd

```bash
# Export flows from lab interface (eth0 or ens3) to collector on localhost
sudo softflowd -i eth0 -n 127.0.0.1:2055 -v 9 -t 30

# Export to remote collector
sudo softflowd -i eth0 -n 192.168.56.100:2055 -v 9
```

## Verify Flows Are Received

On collector host:
```bash
ls -lh /var/cache/nfdump/
# Files should appear and grow after softflowd starts
```

## Important Notes

- **Use only on interfaces you own or have authorization to monitor**
- **Never capture production network traffic without explicit approval**
- softflowd captures metadata only — not full packet payloads
- Stop with: `sudo pkill softflowd`
- For lab: use dedicated lab VLAN or host-only VM interface

## Lab Interface Selection

```bash
# List interfaces
ip link show

# Lab examples:
# eth0     — lab VM main interface
# ens3     — alternative naming
# virbr0   — libvirt/KVM bridge (VMs share this)
# vboxnet0 — VirtualBox host-only
```
