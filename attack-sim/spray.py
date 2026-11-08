"""BForce AI - password spraying simulator.

One IP tries a couple of common passwords on many usernames (password-major order,
like a real spray). Only for YOUR OWN test app; refuses non-localhost targets by default.
Usage:  python attack-sim/spray.py
"""
import argparse
import sys
import time
from collections import Counter
from urllib.parse import urlparse

import requests

USERNAMES = [
    "alice", "bob", "carol", "dave", "erin", "frank",          # real demo users
    "admin", "root", "test", "user", "guest", "info", "support", "sales", "office", "service",
    "operator", "manager", "backup", "web", "john", "mary", "james", "linda", "michael",
    "sarah", "david", "laura", "robert", "emma", "daniel", "olivia", "paul", "sophia",
    "mark", "grace", "peter", "hannah", "steven", "chloe", "kevin", "julia", "brian",
    "nina", "george", "zoe", "oscar", "ivy", "victor", "wendy",
]
PASSWORDS = ["Password1", "Welcome123!"]

p = argparse.ArgumentParser(description="Password spraying simulator for the BForce demo app")
p.add_argument("--url", default="http://localhost:5000/login")
p.add_argument("--ip", default="203.0.113.20", help="fake attacker IP (sent as X-Sim-IP)")
p.add_argument("--gap", type=float, default=0.0, help="seconds between attempts")
p.add_argument("--stop-after-blocks", type=int, default=5)
p.add_argument("--i-own-this-target", action="store_true",
               help="allow a non-localhost URL (only for servers you own)")
args = p.parse_args()

host = urlparse(args.url).hostname
if host not in ("localhost", "127.0.0.1") and not args.i_own_this_target:
    sys.exit(f"Refusing to attack {host}. Only test systems you own (see --i-own-this-target).")

attempts = [(u, pw) for pw in PASSWORDS for u in USERNAMES]
print(f"Spraying {len(PASSWORDS)} passwords across {len(USERNAMES)} usernames from {args.ip}...\n")

session = requests.Session()
counts = Counter()
first_block = None
blocks = 0
found = None
start = time.monotonic()

for i, (user, pw) in enumerate(attempts, 1):
    if i > 1 and args.gap:
        time.sleep(args.gap)
    try:
        r = session.post(args.url, json={"username": user, "password": pw},
                         headers={"X-Sim-IP": args.ip, "User-Agent": "bforce-spray-sim/1.0"},
                         timeout=40)
    except requests.RequestException as exc:
        counts["error"] += 1
        print(f"  attempt {i}: error {exc}")
        continue
    counts[r.status_code] += 1
    if r.status_code == 200:
        found = (i, user)
        print(f"!! Password FOUND for {user} at attempt {i}: the spray was NOT stopped.")
        break
    if r.status_code == 403:
        if first_block is None:
            first_block = (i, time.monotonic() - start)
            print(f">> BLOCKED at attempt {i}, {first_block[1]:.1f}s after start")
        blocks += 1
        if blocks >= args.stop_after_blocks:
            break
    elif i % 10 == 0:
        print(f"  {i} attempts sent, still not blocked...")

elapsed = time.monotonic() - start
print("\n=== Spray summary ===")
print(f"Attempts sent: {sum(counts.values())} in {elapsed:.1f}s")
print(f"Responses:     {dict(counts)}")
if first_block:
    print(f"First block:   attempt {first_block[0]} at {first_block[1]:.1f}s")
if first_block and not found:
    print("PASS: spraying IP was blocked")
else:
    print("FAIL: spraying IP was never blocked" if not first_block else "FAIL: a password was found")
    sys.exit(1)
