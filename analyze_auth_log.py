#!/usr/bin/env python3
"""
Parse auth.log, count 'Failed password' events per IP, print a report, and write
a JSON alert file (alerts.json) for every IP that exceeds the failure threshold.

Usage:
    python3 analyze_auth_log.py                      # defaults: auth.log, threshold 5
    python3 analyze_auth_log.py auth.log -t 10       # stricter/looser policy
    python3 analyze_auth_log.py auth.log -o out.json # custom output file
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 1. THRESHOLD VARIABLE: change this to adjust the security policy.
#    An IP is flagged when its failed attempts EXCEED this number (count > THRESHOLD).
#    It can also be overridden at run time with:  -t / --threshold
# ---------------------------------------------------------------------------
THRESHOLD = 5

ALERT_TYPE = "Potential Brute Force Attack"
DEFAULT_LOG = "auth.log"
DEFAULT_OUTPUT = "alerts.json"

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<port>\d+)"
)


def parse_failures(path):
    """Return {ip: {"count", "users", "first_seen", "last_seen"}} for failed logins."""
    stats = {}
    with open(path) as f:
        for line in f:
            match = FAILED_RE.search(line)
            if not match:
                continue  # skips 'Accepted password' and anything else
            ip = match.group("ip")
            stamp = line[:15].strip()  # syslog stamp, e.g. 'Nov 16 00:03:54'
            entry = stats.setdefault(
                ip, {"count": 0, "users": set(), "first_seen": stamp, "last_seen": stamp}
            )
            entry["count"] += 1
            entry["users"].add(match.group("user"))
            entry["last_seen"] = stamp
    return stats


def alert_level(count, threshold):
    """Severity scales with the threshold, so changing policy keeps levels meaningful."""
    if count >= threshold * 10:
        return "CRITICAL"
    if count >= threshold * 4:
        return "HIGH"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# 2. COMPARE aggregated failure counts against the threshold.
# ---------------------------------------------------------------------------
def build_alerts(stats, threshold):
    """Return a list of alert dicts for IPs whose failures exceed the threshold."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    alerts = []
    for ip, s in stats.items():
        if s["count"] > threshold:
            alerts.append({
                "timestamp": now,
                "source_ip": ip,
                "alert_type": ALERT_TYPE,
                "alert_level": alert_level(s["count"], threshold),
                "failed_attempts": s["count"],
                "threshold": threshold,
                "unique_usernames_tried": len(s["users"]),
                "usernames_tried": sorted(s["users"]),
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
            })
    alerts.sort(key=lambda a: a["failed_attempts"], reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# 3 + 4. FORMAT as standard JSON and SAVE to alerts.json.
# ---------------------------------------------------------------------------
def write_alerts(alerts, stats, threshold, log_path, out_path):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_log": log_path,
        "threshold": threshold,
        "total_failed_attempts": sum(s["count"] for s in stats.values()),
        "unique_ips_with_failures": len(stats),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def print_report(stats, threshold, alerts):
    total = sum(s["count"] for s in stats.values())
    print("=" * 66)
    print(" SSH FAILED LOGIN REPORT")
    print("=" * 66)
    print(f" Total failed attempts : {total}")
    print(f" Unique source IPs     : {len(stats)}")
    print(f" Alert threshold       : more than {threshold} failures")
    print(f" IPs flagged           : {len(alerts)}")
    print("-" * 66)
    print(f" {'IP ADDRESS':<18}{'FAILURES':>9}{'USERS':>7}   {'LEVEL':<9} STATUS")
    print("-" * 66)

    levels = {a["source_ip"]: a["alert_level"] for a in alerts}
    ranked = sorted(stats.items(), key=lambda item: item[1]["count"], reverse=True)
    for ip, s in ranked[:10]:
        if ip in levels:
            print(f" {ip:<18}{s['count']:>9}{len(s['users']):>7}   {levels[ip]:<9} {ALERT_TYPE}")
        else:
            print(f" {ip:<18}{s['count']:>9}{len(s['users']):>7}   {'-':<9} -")
    print("=" * 66)


def parse_args():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts and write alerts.json")
    p.add_argument("log_file", nargs="?", default=DEFAULT_LOG, help=f"log to analyze (default: {DEFAULT_LOG})")
    p.add_argument("-t", "--threshold", type=int, default=THRESHOLD,
                   help=f"alert when failures exceed this number (default: {THRESHOLD})")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"alert file (default: {DEFAULT_OUTPUT})")
    args = p.parse_args()
    if args.threshold < 1:
        p.error("threshold must be 1 or higher")
    return args


def main():
    args = parse_args()
    try:
        stats = parse_failures(args.log_file)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.log_file} (run generate_auth_log.py first)")

    alerts = build_alerts(stats, args.threshold)
    write_alerts(alerts, stats, args.threshold, args.log_file, args.output)

    if stats:
        print_report(stats, args.threshold, alerts)
    else:
        print("No failed password entries found.")
    print(f"{len(alerts)} alert(s) written to {args.output}")


if __name__ == "__main__":
    main()
