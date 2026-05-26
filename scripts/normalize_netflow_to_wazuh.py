#!/usr/bin/env python3
"""
normalize_netflow_to_wazuh.py

Reads raw pmacctd JSON output and converts it into normalized JSON
that Wazuh can parse with the custom NetFlow decoder.

Input:  /var/log/netflow/netflow_raw.json
Output: /var/log/netflow/netflow_wazuh.json

Usage:
    python3 normalize_netflow_to_wazuh.py
    python3 normalize_netflow_to_wazuh.py --input /path/to/raw.json --output /path/to/normalized.json
"""

import json
import os
import sys
import argparse
from datetime import datetime


RAW_LOG_PATH = "/var/log/netflow/netflow_raw.json"
NORMALIZED_LOG_PATH = "/var/log/netflow/netflow_wazuh.json"
PROCESSED_MARKER = "/var/log/netflow/.last_processed_line"


def parse_timestamp(ts_string):
    """Convert pmacctd timestamp to ISO 8601 format."""
    try:
        dt = datetime.strptime(ts_string.strip(), "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def calculate_duration(stamp_inserted, stamp_updated):
    """Calculate flow duration in seconds."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        t_start = datetime.strptime(stamp_inserted.strip(), fmt)
        t_end = datetime.strptime(stamp_updated.strip(), fmt)
        delta = (t_end - t_start).total_seconds()
        return max(int(delta), 0)
    except (ValueError, AttributeError):
        return 0


def normalize_record(raw_record):
    """Convert a raw pmacctd record to normalized Wazuh format."""
    stamp_inserted = raw_record.get("stamp_inserted", "")
    stamp_updated = raw_record.get("stamp_updated", stamp_inserted)

    normalized = {
        "timestamp": parse_timestamp(stamp_inserted),
        "netflow": {
            "src_ip": raw_record.get("ip_src", "0.0.0.0"),
            "dst_ip": raw_record.get("ip_dst", "0.0.0.0"),
            "src_port": int(raw_record.get("port_src", 0)),
            "dst_port": int(raw_record.get("port_dst", 0)),
            "protocol": raw_record.get("ip_proto", "unknown"),
            "packets": int(raw_record.get("packets", 0)),
            "bytes": int(raw_record.get("bytes", 0)),
            "duration_sec": calculate_duration(stamp_inserted, stamp_updated)
        }
    }
    return normalized


def get_last_processed_line():
    """Read the last processed line number."""
    try:
        with open(PROCESSED_MARKER, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def set_last_processed_line(line_number):
    """Save the last processed line number."""
    with open(PROCESSED_MARKER, "w") as f:
        f.write(str(line_number))


def main():
    parser = argparse.ArgumentParser(description="Normalize pmacctd NetFlow logs for Wazuh")
    parser.add_argument("--input", default=RAW_LOG_PATH, help="Path to raw pmacctd JSON log")
    parser.add_argument("--output", default=NORMALIZED_LOG_PATH, help="Path to normalized output log")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Raw log file not found: {args.input}")
        sys.exit(1)

    last_line = get_last_processed_line()
    processed_count = 0
    current_line = 0

    with open(args.input, "r") as infile, open(args.output, "a") as outfile:
        for line in infile:
            current_line += 1

            if current_line <= last_line:
                continue

            line = line.strip()
            if not line:
                continue

            try:
                raw_record = json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed JSON at line {current_line}")
                continue

            normalized = normalize_record(raw_record)
            outfile.write(json.dumps(normalized) + "\n")
            processed_count += 1

    set_last_processed_line(current_line)
    print(f"[+] Processed {processed_count} new records (lines {last_line + 1} to {current_line})")


if __name__ == "__main__":
    main()
