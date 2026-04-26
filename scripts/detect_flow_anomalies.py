#!/usr/bin/env python3
"""
detect_flow_anomalies.py
=========================
NetFlow Anomaly Tagger for Wazuh
Project: Network Flow Monitoring and Anomaly Detection with Wazuh
Author:  Dimas Qi Ramadhani

Description:
    Reads normalized NetFlow JSON lines, applies behavioral detection logic,
    and outputs enriched JSON with anomaly.tags populated.

    Anomaly tags are used by Wazuh custom rules (117001-117009) to classify
    the event type without requiring complex in-Wazuh logic.

Anomaly Tags Produced:
    possible_port_scan        - Many unique dst ports from one source in window
    high_outbound_bytes       - Outbound bytes exceed threshold from one source
    possible_beaconing        - Repeated connections to same dst at regular intervals
    possible_lateral_movement - Internal east-west on admin ports
    suspicious_dns_flow       - High DNS flow count from one source
    possible_dos_pattern      - High packets to single destination

Security Note:
    This script performs behavioral analysis on flow metadata only.
    No network connections are made. All detection is based on
    statistical patterns in the input flow data.
"""

import sys
import json
import os
import argparse
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Set

# =============================================================================
# Thresholds — load from environment or use defaults
# =============================================================================
PORTSCAN_UNIQUE_PORT_THRESHOLD  = int(os.environ.get("PORTSCAN_UNIQUE_PORT_THRESHOLD", "20"))
EXTERNAL_BYTES_THRESHOLD        = int(os.environ.get("EXTERNAL_TRAFFIC_THRESHOLD_BYTES", "50_000_000"))
BEACON_MIN_EVENTS               = int(os.environ.get("BEACON_MIN_EVENTS", "5"))
BEACON_MAX_INTERVAL_VARIATION   = float(os.environ.get("BEACON_MAX_INTERVAL_VARIATION", "30.0"))  # seconds
DNS_FLOW_COUNT_THRESHOLD        = int(os.environ.get("DNS_FLOW_COUNT_THRESHOLD", "100"))
LATERAL_MOVEMENT_PORTS: Set[str] = set(
    os.environ.get("LATERAL_MOVEMENT_PORTS", "22,445,3389,5985,5986,1433,3306").split(",")
)
DOS_PACKET_THRESHOLD            = int(os.environ.get("DOS_PACKET_THRESHOLD", "100_000"))

# =============================================================================
# In-memory state for windowed analysis
# =============================================================================
class FlowState:
    def __init__(self):
        # Port scan: src_ip -> set of unique dst ports
        self.src_dst_ports: Dict[str, Set[str]] = defaultdict(set)
        # High outbound: src_ip -> total bytes to external
        self.src_outbound_bytes: Dict[str, int] = defaultdict(int)
        # Beaconing: (src_ip, dst_ip, dst_port) -> list of timestamps
        self.connection_times: Dict[tuple, List[float]] = defaultdict(list)
        # DNS flow count: src_ip -> count
        self.dns_flow_count: Dict[str, int] = defaultdict(int)
        # DoS: dst_ip -> packet count
        self.dst_packet_count: Dict[str, int] = defaultdict(int)

state = FlowState()


def detect_port_scan(event: dict) -> bool:
    """True if source IP has connected to many distinct destination ports."""
    src  = event.get("source", {}).get("ip", "")
    dst_port = event.get("destination", {}).get("port", "")
    if not src or not dst_port:
        return False
    state.src_dst_ports[src].add(dst_port)
    return len(state.src_dst_ports[src]) >= PORTSCAN_UNIQUE_PORT_THRESHOLD


def detect_high_outbound(event: dict) -> bool:
    """True if source IP has sent more than threshold bytes externally."""
    direction = event.get("flow", {}).get("direction", "")
    if direction != "internal_to_external":
        return False
    src   = event.get("source", {}).get("ip", "")
    bytes_= event.get("network", {}).get("bytes", 0)
    state.src_outbound_bytes[src] += bytes_
    return state.src_outbound_bytes[src] >= EXTERNAL_BYTES_THRESHOLD


def detect_beaconing(event: dict) -> bool:
    """True if (src, dst, dport) shows regular interval connections."""
    src  = event.get("source", {}).get("ip", "")
    dst  = event.get("destination", {}).get("ip", "")
    dport = event.get("destination", {}).get("port", "")
    ts_str = event.get("@timestamp", "")

    if not (src and dst and dport and ts_str):
        return False

    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False

    key = (src, dst, dport)
    state.connection_times[key].append(ts)
    times = sorted(state.connection_times[key])

    if len(times) < BEACON_MIN_EVENTS:
        return False

    # Calculate intervals between consecutive connections
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
    if not intervals:
        return False

    avg_interval = sum(intervals) / len(intervals)
    variation    = max(abs(iv - avg_interval) for iv in intervals)

    # Beaconing: regular interval with low variation and avg > 30s
    return avg_interval > 30 and variation < BEACON_MAX_INTERVAL_VARIATION


def detect_lateral_movement(event: dict) -> bool:
    """True if internal-to-internal flow on admin/service ports."""
    direction = event.get("flow", {}).get("direction", "")
    dport     = event.get("destination", {}).get("port", "")
    return direction == "internal_to_internal" and str(dport) in LATERAL_MOVEMENT_PORTS


def detect_suspicious_dns(event: dict) -> bool:
    """True if source IP has generated excessive DNS flows."""
    service = event.get("service", {}).get("name", "")
    proto   = event.get("flow", {}).get("protocol", "")
    dport   = event.get("destination", {}).get("port", "")

    if not (service == "DNS" or (proto == "UDP" and dport == "53")):
        return False

    src = event.get("source", {}).get("ip", "")
    state.dns_flow_count[src] += 1
    return state.dns_flow_count[src] >= DNS_FLOW_COUNT_THRESHOLD


def detect_dos_pattern(event: dict) -> bool:
    """True if destination IP has received excessive packets."""
    dst     = event.get("destination", {}).get("ip", "")
    packets = event.get("network", {}).get("packets", 0)
    state.dst_packet_count[dst] += packets
    return state.dst_packet_count[dst] >= DOS_PACKET_THRESHOLD


# =============================================================================
# Main enrichment loop
# =============================================================================
def enrich_events(input_stream, output_stream) -> tuple:
    """Read normalized flow JSON lines, tag anomalies, write enriched JSON."""
    processed = errors = tagged = 0

    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[WARN] JSON parse error: {e}", file=sys.stderr)
            errors += 1
            continue

        tags: List[str] = list(event.get("anomaly", {}).get("tags", []))

        if detect_port_scan(event):
            if "possible_port_scan" not in tags:
                tags.append("possible_port_scan")

        if detect_high_outbound(event):
            if "high_outbound_bytes" not in tags:
                tags.append("high_outbound_bytes")

        if detect_beaconing(event):
            if "possible_beaconing" not in tags:
                tags.append("possible_beaconing")

        if detect_lateral_movement(event):
            if "possible_lateral_movement" not in tags:
                tags.append("possible_lateral_movement")

        if detect_suspicious_dns(event):
            if "suspicious_dns_flow" not in tags:
                tags.append("suspicious_dns_flow")

        if detect_dos_pattern(event):
            if "possible_dos_pattern" not in tags:
                tags.append("possible_dos_pattern")

        event.setdefault("anomaly", {})["tags"] = tags
        if tags:
            tagged += 1

        print(json.dumps(event), file=output_stream)
        processed += 1

    return processed, errors, tagged


def main():
    parser = argparse.ArgumentParser(description="Detect flow anomalies and tag events")
    parser.add_argument("--input",  "-i", help="Input normalized JSON file (default: stdin)")
    parser.add_argument("--output", "-o", help="Output enriched JSON file (default: stdout)")
    args = parser.parse_args()

    in_stream  = open(args.input)  if args.input  else sys.stdin
    out_stream = open(args.output, "a") if args.output else sys.stdout

    try:
        processed, errors, tagged = enrich_events(in_stream, out_stream)
        print(
            f"[INFO] Processed: {processed} | Errors: {errors} | Tagged anomalies: {tagged}",
            file=sys.stderr
        )
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()


if __name__ == "__main__":
    main()
