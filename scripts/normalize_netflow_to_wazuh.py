#!/usr/bin/env python3
"""
normalize_netflow_to_wazuh.py

Reads raw pmacctd JSON output and converts it into flat normalized JSON
that Wazuh can parse with the built-in JSON decoder.

Input:  /var/log/netflow/netflow_raw.json
Output: /var/log/netflow/netflow_wazuh.json

Filtering:
- Multicast addresses (224.0.0.0/4)
- Broadcast (255.255.255.255)
- Loopback (127.x.x.x)
- IPv6 link-local and multicast (fe80::, ff::)
- Internal cloud/lab subnet (configure INTERNAL_PREFIX below)

pmacctd aggregate config required:
  aggregate: src_host, dst_host, src_port, dst_port, proto, tos, timestamp_start, timestamp_end

Output format: flat JSON with integer fields (nf_bytes, nf_packets, nf_src_port, nf_dst_port)
Note: Flat JSON required because Wazuh 4.x does not support dot notation in rule <field> tags.

Usage:
    python3 normalize_netflow_to_wazuh.py
    python3 normalize_netflow_to_wazuh.py --input /path/to/raw.json --output /path/to/out.json
"""

import json
import os
import sys
import argparse
from datetime import datetime

RAW_LOG_PATH = "/var/log/netflow/netflow_raw.json"
NORMALIZED_LOG_PATH = "/var/log/netflow/netflow_wazuh.json"
PROCESSED_MARKER = "/var/log/netflow/.last_processed_line"

# Exact IPs to exclude
EXCLUDED_IPS = {"255.255.255.255", "0.0.0.0"}

# Internal subnet prefix - adjust to match your environment
INTERNAL_PREFIX = "160.22."

def is_excluded(ip):
    if not ip or ip in EXCLUDED_IPS:
        return True
    if ip.startswith("127."):
        return True
    if ip.startswith("fe80") or ip.startswith("ff"):
        return True
    if ip.startswith(INTERNAL_PREFIX):
        return True
    try:
        if 224 <= int(ip.split(".")[0]) <= 239:
            return True
    except (ValueError, IndexError):
        pass
    return False

def parse_timestamp(ts):
    if not ts or ts.startswith("0000"):
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts.strip(), fmt).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, AttributeError):
            pass
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def calc_duration(t1, t2):
    if not t1 or not t2 or t2.startswith("0000"):
        return 0
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            d = (datetime.strptime(t2.strip(), fmt) - datetime.strptime(t1.strip(), fmt)).total_seconds()
            return max(int(d), 0)
        except (ValueError, AttributeError):
            pass
    return 0

def normalize(r):
    t1 = r.get("timestamp_start") or r.get("stamp_inserted", "")
    t2 = r.get("timestamp_end") or r.get("stamp_updated", t1)
    return {
        "timestamp":   parse_timestamp(t1),
        "nf_src_ip":   r.get("ip_src", "0.0.0.0"),
        "nf_dst_ip":   r.get("ip_dst", "0.0.0.0"),
        "nf_src_port": int(r.get("port_src", 0)),
        "nf_dst_port": int(r.get("port_dst", 0)),
        "nf_protocol": r.get("ip_proto", "unknown"),
        "nf_packets":  int(r.get("packets", 0)),
        "nf_bytes":    int(r.get("bytes", 0)),
        "nf_duration": int(calc_duration(t1, t2))
    }

def get_last():
    try:
        return int(open(PROCESSED_MARKER).read().strip())
    except (FileNotFoundError, ValueError):
        return 0

def set_last(n):
    with open(PROCESSED_MARKER, "w") as f:
        f.write(str(n))

def main():
    parser = argparse.ArgumentParser(description="Normalize pmacctd NetFlow logs for Wazuh")
    parser.add_argument("--input", default=RAW_LOG_PATH)
    parser.add_argument("--output", default=NORMALIZED_LOG_PATH)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Raw log not found: {args.input}")
        sys.exit(0)

    last, current, count, skipped = get_last(), 0, 0, 0

    with open(args.input) as f, open(args.output, "a") as out:
        for line in f:
            current += 1
            if current <= last:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                src = r.get("ip_src", "")
                dst = r.get("ip_dst", "")
                if is_excluded(src) or is_excluded(dst):
                    skipped += 1
                    continue
                out.write(json.dumps(normalize(r)) + "\n")
                count += 1
            except (json.JSONDecodeError, KeyError):
                pass

    set_last(current)
    print(f"[+] Processed {count} new records, skipped {skipped} (filtered)")

if __name__ == "__main__":
    main()