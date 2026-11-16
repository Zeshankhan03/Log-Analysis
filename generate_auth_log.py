#!/usr/bin/env python3
"""Generate a simulated Linux auth.log with brute-force traffic mixed in."""
import random
from datetime import datetime, timedelta

random.seed(42)  # same output every run; remove for true randomness

LOG_FILE = "auth.log"
TOTAL_LINES = 500
HOSTNAME = "webserver01"

# Normal users who legitimately log in
VALID_USERS = ["alice", "bob", "carol", "deploy"]
# Usernames attackers typically guess
GUESSED_USERS = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "pi"]

# A few "attacker" IPs that will be heavily weighted toward failures
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.99"]


def random_ip():
    """Random public-looking IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def build_line(ts):
    """Return one syslog-style line for timestamp ts."""
    pid = random.randint(1000, 40000)
    port = random.randint(1024, 65535)
    stamp = ts.strftime("%b %d %H:%M:%S")
    prefix = f"{stamp} {HOSTNAME} sshd[{pid}]:"

    roll = random.random()
    if roll < 0.55:
        # Brute-force attempt from one of the attacker IPs
        ip = random.choice(ATTACKER_IPS)
        user = random.choice(GUESSED_USERS)
        if user in ("root", "admin"):
            return f"{prefix} Failed password for {user} from {ip} port {port} ssh2"
        return f"{prefix} Failed password for invalid user {user} from {ip} port {port} ssh2"
    elif roll < 0.75:
        # Random one-off failure (typo by a normal user or a scanner)
        ip = random_ip()
        user = random.choice(VALID_USERS + GUESSED_USERS)
        return f"{prefix} Failed password for {user} from {ip} port {port} ssh2"
    else:
        # Successful login by a legitimate user
        ip = random_ip()
        user = random.choice(VALID_USERS)
        return f"{prefix} Accepted password for {user} from {ip} port {port} ssh2"


def main():
    ts = datetime(2026, 11, 16, 0, 0, 0)
    with open(LOG_FILE, "w") as f:
        for _ in range(TOTAL_LINES):
            ts += timedelta(seconds=random.randint(1, 120))
            f.write(build_line(ts) + "\n")
    print(f"Wrote {TOTAL_LINES} log lines to {LOG_FILE}")


if __name__ == "__main__":
    main()
