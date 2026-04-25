#!/usr/bin/env python3
"""
generate_safe_netflow_test_events.py
=====================================
Synthetic NetFlow Event Generator for Wazuh Lab Validation
Project: Network Flow Monitoring and Anomaly Detection with Wazuh
Author:  Dimas Qi Ramadhani

Description:
    Generates realistic-looking but completely synthetic normalized NetFlow
    JSON events to validate Wazuh custom rules WITHOUT needing a real
    NetFlow exporter or live network traffic.

    ALL IP addresses use RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x,
    203.0.113.x) — these are reserved for documentation and cannot route on
    the real internet.

Security Note:
    This script generates NO real network traffic.
    No connections are made to any host.
    All data is synthetic and safe for any lab environment.
    This is NOT a network attack tool.

Usage:
    python3 generate_safe_netflow_test_events.py
    python3 generate_safe_netflow_test_events.py --output /var/log/netflow/netflow-wazuh.json
    python3 generate_safe_netflow_test_events.py --scenario beaconing --count 10
"""

import json
import sys
import argparse
import os
import random
import time
from datetime import datetime, timezone, timedelta

# Documentation-only IP ranges per RFC 5737 and RFC 3849
INTERNAL_IP_RANGE  = ["192.168.56.{}".format(i) for i in range(10, 40)]
EXTERNAL_IP_RANGE  = ["203.0.113.{}".format(i) for i in range(1, 50)]
INTERNAL_NETWORK   = "192.168.56.0/24"

COLLECTOR_NAME = "lab-collector-01"
EXPORTER_IP    = "192.168.56.1"

def ts_now(offset_seconds: float = 0.0) -> str:
    """Return ISO8601 UTC timestamp with optional offset."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def base_event(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               proto: str, bytes_: int, packets: int, duration: float,
               service: str, direction: str, flags: str = "",
               timestamp: str = None, tags: list = None) -> dict:
    return {
        "@timestamp":       timestamp or ts_now(),
        "source":           "netflow",
        "collector.name":   COLLECTOR_NAME,
        "exporter.ip":      EXPORTER_IP,
        "flow.protocol":    proto,
        "source.ip":        src_ip,
        "source.port":      str(src_port),
        "destination.ip":   dst_ip,
        "destination.port": str(dst_port),
        "network.bytes":    bytes_,
        "network.packets":  packets,
        "event.duration":   round(duration, 3),
        "tcp.flags":        flags,
        "flow.direction":   direction,
        "internal.src":     direction.startswith("internal"),
        "internal.dst":     direction.endswith("internal"),
        "service.name":     service,
        "event.type":       "network",
        "event.category":   "network_traffic",
        "anomaly.tags":     tags or [],
    }


# =============================================================================
# Scenario generators
# =============================================================================

def scenario_port_scan(count: int = 25) -> list:
    """Generate port scan flow pattern — many unique dst ports from one source."""
    print(f"[GEN] Port scan scenario: {count} flows from one source to many ports", file=sys.stderr)
    print(f"  Expected Wazuh rule: 117001 (possible_port_scan)", file=sys.stderr)

    src = random.choice(INTERNAL_IP_RANGE)
    dst = random.choice(INTERNAL_IP_RANGE)
    while dst == src:
        dst = random.choice(INTERNAL_IP_RANGE)

    events = []
    ports = random.sample(range(1, 65535), count)
    for i, port in enumerate(ports):
        events.append(base_event(
            src_ip=src, dst_ip=dst, src_port=random.randint(40000, 60000),
            dst_port=port, proto="TCP", bytes_=60, packets=1,
            duration=0.001, service="OTHER", direction="internal_to_internal",
            flags="SYN", timestamp=ts_now(float(i)), tags=["possible_port_scan"]
        ))
    return events


def scenario_high_outbound(count: int = 5) -> list:
    """Generate high outbound traffic — large byte transfers to external."""
    print(f"[GEN] High outbound scenario: {count} large flows to external", file=sys.stderr)
    print(f"  Expected Wazuh rule: 117002 (high_outbound_bytes)", file=sys.stderr)

    src = random.choice(INTERNAL_IP_RANGE)
    dst = random.choice(EXTERNAL_IP_RANGE)

    events = []
    for i in range(count):
        bytes_ = random.randint(10_000_000, 100_000_000)
        events.append(base_event(
            src_ip=src, dst_ip=dst, src_port=random.randint(40000, 60000),
            dst_port=443, proto="TCP", bytes_=bytes_, packets=bytes_//1400,
            duration=random.uniform(60, 3600), service="HTTPS",
            direction="internal_to_external", flags="SYN,ACK,FIN",
            timestamp=ts_now(float(i * 60)), tags=["high_outbound_bytes"]
        ))
    return events


def scenario_beaconing(count: int = 8, interval: float = 300.0) -> list:
    """Generate beaconing pattern — periodic connections to same dst."""
    print(f"[GEN] Beaconing scenario: {count} flows every {interval}s to same destination", file=sys.stderr)
    print(f"  Expected Wazuh rule: 117003 (possible_beaconing)", file=sys.stderr)

    src = random.choice(INTERNAL_IP_RANGE)
    dst = random.choice(EXTERNAL_IP_RANGE)
    port = random.choice([80, 443, 8080])

    events = []
    for i in range(count):
        jitter = random.uniform(-10, 10)
        events.append(base_event(
            src_ip=src, dst_ip=dst, src_port=random.randint(40000, 60000),
            dst_port=port, proto="TCP",
            bytes_=random.randint(400, 600), packets=4,
            duration=random.uniform(0.5, 2.0), service="HTTPS" if port == 443 else "HTTP",
            direction="internal_to_external", flags="SYN,ACK,FIN",
            timestamp=ts_now(float(i * interval + jitter)),
            tags=["possible_beaconing"]
        ))
    return events


def scenario_lateral_movement(count: int = 6) -> list:
    """Generate lateral movement — internal host to multiple internal admin ports."""
    print(f"[GEN] Lateral movement scenario: {count} admin port flows internal-to-internal", file=sys.stderr)
    print(f"  Expected Wazuh rule: 117004 (lateral movement)", file=sys.stderr)

    src   = random.choice(INTERNAL_IP_RANGE)
    dsts  = random.sample([ip for ip in INTERNAL_IP_RANGE if ip != src], min(count, len(INTERNAL_IP_RANGE)-1))
    ports = [445, 3389, 22, 5985, 445, 3389]

    events = []
    for i, (dst, port) in enumerate(zip(dsts, ports)):
        svc = {445: "SMB", 3389: "RDP", 22: "SSH", 5985: "WinRM-HTTP"}.get(port, "OTHER")
        events.append(base_event(
            src_ip=src, dst_ip=dst, src_port=random.randint(40000, 60000),
            dst_port=port, proto="TCP", bytes_=random.randint(2000, 8000),
            packets=random.randint(10, 50), duration=random.uniform(0.5, 5.0),
            service=svc, direction="internal_to_internal", flags="SYN,ACK",
            timestamp=ts_now(float(i * 15)), tags=["possible_lateral_movement"]
        ))
    return events


def scenario_suspicious_dns(count: int = 120) -> list:
    """Generate suspicious DNS flow volume from one host."""
    print(f"[GEN] Suspicious DNS scenario: {count} DNS flows from one source", file=sys.stderr)
    print(f"  Expected Wazuh rule: 117005 (suspicious_dns_flow)", file=sys.stderr)

    src     = random.choice(INTERNAL_IP_RANGE)
    dns_svr = "8.8.8.8"

    events = []
    for i in range(count):
        events.append(base_event(
            src_ip=src, dst_ip=dns_svr, src_port=random.randint(40000, 60000),
            dst_port=53, proto="UDP", bytes_=random.randint(60, 300),
            packets=1, duration=0.05, service="DNS",
            direction="internal_to_external", flags="",
            timestamp=ts_now(float(i * 0.5)), tags=["suspicious_dns_flow"]
        ))
    return events


# =============================================================================
# Main
# =============================================================================
SCENARIOS = {
    "port_scan":       scenario_port_scan,
    "high_outbound":   scenario_high_outbound,
    "beaconing":       scenario_beaconing,
    "lateral_movement": scenario_lateral_movement,
    "dns":             scenario_suspicious_dns,
    "all":             None,
}


def main():
    parser = argparse.ArgumentParser(description="Generate safe synthetic NetFlow test events")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()), default="all",
                        help="Which scenario to generate (default: all)")
    parser.add_argument("--count", type=int, default=None,
                        help="Override event count for scenario")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    out_stream = open(args.output, "a") if args.output else sys.stdout

    try:
        all_events = []
        if args.scenario == "all":
            all_events.extend(scenario_port_scan())
            all_events.extend(scenario_high_outbound())
            all_events.extend(scenario_beaconing())
            all_events.extend(scenario_lateral_movement())
            all_events.extend(scenario_suspicious_dns())
        else:
            fn = SCENARIOS[args.scenario]
            all_events.extend(fn(args.count) if args.count else fn())

        for event in all_events:
            print(json.dumps(event), file=out_stream)

        print(f"\n[INFO] Generated {len(all_events)} synthetic flow events", file=sys.stderr)
        print("[INFO] Check Wazuh Dashboard: rule.groups:netflow", file=sys.stderr)

    finally:
        if args.output:
            out_stream.close()


if __name__ == "__main__":
    main()
