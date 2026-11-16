#!/usr/bin/env python3
"""Parse auth.log, count 'Failed password' events per IP, print a report."""
import re
import sys

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
THRESHOLD = 3  # failures at/above this count get flagged as suspected brute force

# Matches both:
#   Failed password for root from 1.2.3.4 port 5555 ssh2
#   Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<port>\d+)"
)


def parse_failures(path):
    """Return ({ip: failure_count}, {ip: set_of_usernames_tried})."""
    counts = {}
    users = {}
    with open(path) as f:
        for line in f:
            match = FAILED_RE.search(line)
            if not match:
                continue  # skips 'Accepted password' and anything else
            ip = match.group("ip")
            user = match.group("user")
            counts[ip] = counts.get(ip, 0) + 1
            users.setdefault(ip, set()).add(user)
    return counts, users


def print_report(counts, users):
    total = sum(counts.values())
    print("=" * 62)
    print(" SSH FAILED LOGIN REPORT")
    print("=" * 62)
    print(f" Total failed attempts : {total}")
    print(f" Unique source IPs     : {len(counts)}")
    print(f" Flag threshold        : {THRESHOLD}+ failures")
    print("-" * 62)
    print(f" {'IP ADDRESS':<18}{'FAILURES':>9}{'USERS TRIED':>13}   STATUS")
    print("-" * 62)

    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    for ip, n in ranked[:10]:
        status = "SUSPECTED BRUTE FORCE" if n >= THRESHOLD else "-"
        print(f" {ip:<18}{n:>9}{len(users[ip]):>13}   {status}")
    print("=" * 62)


def main():
    try:
        counts, users = parse_failures(LOG_FILE)
    except FileNotFoundError:
        sys.exit(f"File not found: {LOG_FILE} (run generate_auth_log.py first)")
    if not counts:
        sys.exit("No failed password entries found.")
    print_report(counts, users)


if __name__ == "__main__":
    main()
