"""BForce AI - brute-force attack simulator.

Only for YOUR OWN test app. By default it refuses any target that is not localhost.
Usage:  python attack-sim/attack.py
"""
import argparse
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import requests

HERE = Path(__file__).parent

p = argparse.ArgumentParser(description="Brute-force simulator for the BForce demo app")
p.add_argument("--url", default="http://localhost:5000/login")
p.add_argument("--ip", default="203.0.113.7", help="fake attacker IP (sent as X-Sim-IP)")
p.add_argument("--user", default="alice")
p.add_argument("--wordlist", default=str(HERE / "wordlist.txt"))
p.add_argument("--stop-after-blocks", type=int, default=5)
p.add_argument("--i-own-this-target", action="store_true",
               help="allow a non-localhost URL (only for servers you own)")
args = p.parse_args()

host = urlparse(args.url).hostname
if host not in ("localhost", "127.0.0.1") and not args.i_own_this_target:
    sys.exit(f"Refusing to attack {host}. Only test systems you own (see --i-own-this-target).")

words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
print(f"Attacking user '{args.user}' from {args.ip} with {len(words)} passwords...\n")

session = requests.Session()
counts = Counter()
first_block = None
blocks = 0
start = time.monotonic()

for i, pw in enumerate(words, 1):
    try:
        r = session.post(args.url, json={"username": args.user, "password": pw},
                         headers={"X-Sim-IP": args.ip, "User-Agent": "bforce-attack-sim/1.0"},
                         timeout=5)
    except requests.RequestException as exc:
        counts["error"] += 1
        print(f"  attempt {i}: error {exc}")
        continue
    counts[r.status_code] += 1
    if r.status_code == 200:
        print(f"!! Password FOUND at attempt {i}: the attack was NOT stopped in time.")
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
print("\n=== Attack summary ===")
print(f"Attempts sent: {sum(counts.values())} in {elapsed:.1f}s")
print(f"Responses:     {dict(counts)}")
if first_block:
    print(f"First block:   attempt {first_block[0]} at {first_block[1]:.1f}s")
    print("PASS" if first_block[1] <= 10 else "SLOW: blocked, but after more than 10s")
else:
    print("FAIL: attacker was never blocked")
