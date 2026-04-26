#!/usr/bin/env python3
"""
normalize_netflow_to_wazuh.py
==============================
NetFlow / IPFIX Log Normalizer for Wazuh
Project: Network Flow Monitoring and Anomaly Detection with Wazuh
Author:  Dimas Qi Ramadhani

Description:
    Reads flow data from pmacct JSON file (primary) or nfdump text output (legacy),
    and outputs one Wazuh-compatible JSON event per line to stdout or file.

    Primary usage: --pmacct with output from pmacctd direct interface capture.
    Output mode: overwrite (not append) — safe to run repeatedly via cron.

Usage (primary — pmacctd):
    python3 normalize_netflow_to_wazuh.py --pmacct /var/log/netflow/netflow-raw.json --output /var/log/netflow/netflow-wazuh.json

Usage (legacy — nfdump):
    nfdump -r <flowfile> -o csv | python3 normalize_netflow_to_wazuh.py
    python3 normalize_netflow_to_wazuh.py --input flows.txt --output /var/log/netflow/netflow-wazuh.json

Security Note:
    This script processes metadata only — no network payloads.
    Uses dummy IPs from RFC 5737 / RFC 3849 ranges for lab.
    Do not process production flow data without privacy review.
"""

import sys
import json
import ipaddress
import argparse
import re
from datetime import datetime, timezone
from typing import Optional

# =============================================================================
# Configuration — Load from environment or .env (no hardcoded values)
# =============================================================================
import os

INTERNAL_NETWORKS_RAW = os.environ.get(
    "INTERNAL_NETWORKS", "192.168.56.0/24,10.10.10.0/24"
)

try:
    INTERNAL_NETWORKS = [
        ipaddress.ip_network(net.strip(), strict=False)
        for net in INTERNAL_NETWORKS_RAW.split(",")
        if net.strip()
    ]
except ValueError as e:
    print(f"[WARN] Invalid INTERNAL_NETWORKS: {e}. Using defaults.", file=sys.stderr)
    INTERNAL_NETWORKS = [ipaddress.ip_network("192.168.56.0/24")]

COLLECTOR_NAME = os.environ.get("NETFLOW_COLLECTOR_NAME", "lab-collector-01")
EXPORTER_IP    = os.environ.get("NETFLOW_EXPORTER_IP", "192.168.56.1")

# =============================================================================
# Service name lookup
# =============================================================================
SERVICE_MAP = {
    "53":   "DNS",
    "80":   "HTTP",
    "443":  "HTTPS",
    "8080": "HTTP-ALT",
    "8443": "HTTPS-ALT",
    "22":   "SSH",
    "23":   "Telnet",
    "21":   "FTP",
    "25":   "SMTP",
    "587":  "SMTP-STARTTLS",
    "110":  "POP3",
    "143":  "IMAP",
    "3389": "RDP",
    "445":  "SMB",
    "139":  "NetBIOS",
    "135":  "MSRPC",
    "5985": "WinRM-HTTP",
    "5986": "WinRM-HTTPS",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "1521": "Oracle",
    "27017": "MongoDB",
    "6379": "Redis",
    "2181": "Zookeeper",
    "9200": "Elasticsearch",
    "123":  "NTP",
    "161":  "SNMP",
    "162":  "SNMP-Trap",
    "500":  "ISAKMP-IKE",
    "4500": "IPsec-NAT-T",
    "1194": "OpenVPN",
    "1723": "PPTP",
    "119":  "NNTP",
}

def get_service_name(port: str, proto: str) -> str:
    """Return service name from port number."""
    return SERVICE_MAP.get(str(port), "OTHER")


# =============================================================================
# IP helpers
# =============================================================================
def is_internal(ip_str: str) -> bool:
    """Check if IP is within configured internal networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def determine_direction(src_ip: str, dst_ip: str) -> str:
    """Determine flow direction relative to internal network definition."""
    src_int = is_internal(src_ip)
    dst_int = is_internal(dst_ip)
    if src_int and dst_int:
        return "internal_to_internal"
    elif src_int and not dst_int:
        return "internal_to_external"
    elif not src_int and dst_int:
        return "external_to_internal"
    else:
        return "external_to_external"


# =============================================================================
# nfdump text output parser
# =============================================================================
# nfdump -o long or -o csv output format varies by version
# This parser handles the common extended format:
# Date first seen  Duration  Proto  Src IP Addr:Port  Dst IP Addr:Port  Flags  Tos  Packets  Bytes  Flows

NFDUMP_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"  # timestamp
    r"\s+([\d.]+)"                                          # duration
    r"\s+(\w+)"                                             # protocol
    r"\s+([\d.a-fA-F:]+):(\d+)"                            # src ip:port
    r"\s+->\s+([\d.a-fA-F:]+):(\d+)"                       # dst ip:port
    r"(?:\s+(\S+))?"                                        # tcp flags (optional)
    r"(?:\s+\d+)?"                                          # tos (optional)
    r"\s+(\d+)"                                             # packets
    r"\s+([\d.]+\s*[KMGT]?)"                                # bytes (may have unit)
)


def parse_bytes(byte_str: str) -> int:
    """Parse byte string that may include K/M/G suffix."""
    byte_str = byte_str.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for suffix, mult in multipliers.items():
        if byte_str.endswith(suffix):
            return int(float(byte_str[:-1]) * mult)
    try:
        return int(float(byte_str))
    except ValueError:
        return 0


def parse_nfdump_line(line: str) -> Optional[dict]:
    """Parse a single nfdump text output line into a normalized dict."""
    line = line.strip()
    if not line or line.startswith("Date") or line.startswith("Summary") or line.startswith("Time"):
        return None

    m = NFDUMP_LINE_RE.search(line)
    if not m:
        return None

    ts_str, duration, proto, src_ip, src_port, dst_ip, dst_port, flags, packets, bytes_str = (
        m.group(1), m.group(2), m.group(3), m.group(4), m.group(5),
        m.group(6), m.group(7), m.group(8) or "", m.group(9), m.group(10)
    )

    try:
        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

    direction = determine_direction(src_ip, dst_ip)
    service   = get_service_name(dst_port, proto)
    byte_val  = parse_bytes(bytes_str)

    return {
        "@timestamp":  ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "netflow":     "true",
        "collector":   {"name": COLLECTOR_NAME},
        "exporter":    {"ip": EXPORTER_IP},
        "source":      {"ip": src_ip, "port": src_port},
        "destination": {"ip": dst_ip, "port": dst_port},
        "flow":        {"protocol": proto.upper(), "direction": direction},
        "network":     {"bytes": byte_val, "packets": int(packets)},
        "event":       {"duration": float(duration), "type": "network", "category": "network_traffic"},
        "tcp":         {"flags": flags},
        "internal":    {"src": is_internal(src_ip), "dst": is_internal(dst_ip)},
        "service":     {"name": service},
        "anomaly":     {"tags": []},
    }


# =============================================================================
# pmacct JSON output parser
# =============================================================================
def parse_pmacct_record(record: dict) -> Optional[dict]:
    """Normalize a pmacct JSON record."""
    src_ip   = record.get("ip_src", "")
    dst_ip   = record.get("ip_dst", "")
    src_port = int(record.get("port_src", 0))
    dst_port = int(record.get("port_dst", 0))
    proto    = str(record.get("ip_proto", "0"))
    packets  = int(record.get("packets", 0))
    bytes_   = int(record.get("bytes", 0))
    ts_start = record.get("timestamp_start", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Protocol number to name
    # Handles both numeric strings ("6") and name strings ("tcp") from pmacctd
    proto_map = {
        "6": "TCP", "17": "UDP", "1": "ICMP", "47": "GRE", "50": "ESP",
        "2": "IGMP", "58": "ICMPv6", "89": "OSPF", "132": "SCTP",
        "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "igmp": "IGMP",
        "gre": "GRE", "esp": "ESP", "icmpv6": "ICMPv6", "ipv6-icmp": "ICMPv6",
        "ospf": "OSPF", "sctp": "SCTP", "ipv6": "IPv6", "ah": "AH",
        "pim": "PIM", "vrrp": "VRRP",
    }
    proto_name = proto_map.get(proto.lower() if proto.isalpha() else proto, f"PROTO{proto}")

    direction = determine_direction(src_ip, dst_ip)
    service   = get_service_name(dst_port, proto_name)

    return {
        "@timestamp":  ts_start if "T" in ts_start else ts_start,
        "netflow":     "true",
        "collector":   {"name": COLLECTOR_NAME},
        "exporter":    {"ip": EXPORTER_IP},
        "source":      {"ip": src_ip, "port": src_port},
        "destination": {"ip": dst_ip, "port": dst_port},
        "flow":        {"protocol": proto_name, "direction": direction},
        "network":     {"bytes": bytes_, "packets": packets},
        "event":       {"duration": 0.0, "type": "network", "category": "network_traffic"},
        "tcp":         {"flags": ""},
        "internal":    {"src": is_internal(src_ip), "dst": is_internal(dst_ip)},
        "service":     {"name": service},
        "anomaly":     {"tags": []},
    }


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Normalize NetFlow data for Wazuh")
    parser.add_argument("--input", "-i", help="nfdump text output file (default: stdin)")
    parser.add_argument("--pmacct", help="pmacct JSON output file")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    out_stream = open(args.output, "w") if args.output else sys.stdout
    processed = 0
    errors = 0

    try:
        if args.pmacct:
            # pmacct mode
            with open(args.pmacct) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        normalized = parse_pmacct_record(record)
                        if normalized:
                            print(json.dumps(normalized), file=out_stream)
                            processed += 1
                    except (json.JSONDecodeError, KeyError) as e:
                        errors += 1
                        print(f"[WARN] pmacct parse error: {e}", file=sys.stderr)
        else:
            # nfdump text mode
            in_stream = open(args.input) if args.input else sys.stdin
            for line in in_stream:
                try:
                    normalized = parse_nfdump_line(line)
                    if normalized:
                        print(json.dumps(normalized), file=out_stream)
                        processed += 1
                except Exception as e:
                    errors += 1
                    print(f"[WARN] Line parse error: {e}", file=sys.stderr)
            if args.input:
                in_stream.close()

    finally:
        if args.output:
            out_stream.close()

    print(f"[INFO] Processed: {processed} events | Errors: {errors}", file=sys.stderr)


if __name__ == "__main__":
    main()
