"""BForce AI - low-and-slow attack simulator.

One IP sends one wrong password every few seconds: too slow for login-bf,
but it should fill the bigger login-slow bucket. Only for YOUR OWN test app.
Usage:  python attack-sim/slow.py
"""
import argparse
import sys
import time
from collections import Counter
from urllib.parse import urlparse

import requests

p = argparse.ArgumentParser(description="Low-and-slow simulator for the BForce demo app")
p.add_argument("--url", default="http://localhost:5000/login")
p.add_argument("--ip", default="203.0.113.30", help="fake attacker IP (sent as X-Sim-IP)")
p.add_argument("--user", default="alice")
p.add_argument("--gap", type=float, default=5.0, help="seconds between attempts")
p.add_argument("--duration", type=float, default=600, help="seconds to run")
p.add_argument("--stop-after-blocks", type=int, default=3)
p.add_argument("--i-own-this-target", action="store_true",
               help="allow a non-localhost URL (only for servers you own)")
args = p.parse_args()

host = urlparse(args.url).hostname
if host not in ("localhost", "127.0.0.1") and not args.i_own_this_target:
    sys.exit(f"Refusing to attack {host}. Only test systems you own (see --i-own-this-target).")

print(f"Slow attack on '{args.user}' from {args.ip}: one try every {args.gap:.0f}s "
      f"for up to {args.duration:.0f}s...\n")

session = requests.Session()
counts = Counter()
first_block = None
blocks = 0
found = False
start = time.monotonic()
i = 0

while time.monotonic() - start < args.duration:
    i += 1
    try:
        r = session.post(args.url, json={"username": args.user, "password": f"wrong-{i}"},
                         headers={"X-Sim-IP": args.ip, "User-Agent": "bforce-slow-sim/1.0"},
                         timeout=40)
    except requests.RequestException as exc:
        counts["error"] += 1
        print(f"  attempt {i}: error {exc}")
    else:
        counts[r.status_code] += 1
        if r.status_code == 200:
            found = True
            print(f"!! Login succeeded at attempt {i}: unexpected.")
            break
        if r.status_code == 403:
            if first_block is None:
                first_block = (i, time.monotonic() - start)
                print(f">> BLOCKED at attempt {i}, {first_block[1]:.1f}s after start")
            blocks += 1
            if blocks >= args.stop_after_blocks:
                break
        elif i % 6 == 0:
            print(f"  {i} attempts sent ({time.monotonic() - start:.0f}s), still not blocked...")
    time.sleep(args.gap)

elapsed = time.monotonic() - start
print("\n=== Slow attack summary ===")
print(f"Attempts sent: {sum(counts.values())} in {elapsed:.1f}s")
print(f"Responses:     {dict(counts)}")
if first_block:
    print(f"First block:   attempt {first_block[0]} at {first_block[1]:.1f}s")
if first_block and not found:
    print("PASS: slow attacker was blocked")
else:
    print("FAIL: slow attacker was never blocked")
    sys.exit(1)
