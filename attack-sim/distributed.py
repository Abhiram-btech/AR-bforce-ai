"""BForce AI - distributed attack simulator (many IPs, one account).

50 fake IPs each try 3 passwords on one account, so no single IP looks suspicious.
The defence is account throttling in the login app: responses get slower, nobody is banned.
Only for YOUR OWN test app; refuses non-localhost targets by default.
Usage:  python attack-sim/distributed.py
"""
import argparse
import ipaddress
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import requests

HERE = Path(__file__).parent

p = argparse.ArgumentParser(description="Distributed attack simulator for the BForce demo app")
p.add_argument("--url", default="http://localhost:5000/login")
p.add_argument("--user", default="alice")
p.add_argument("--first-ip", default="203.0.113.100")
p.add_argument("--ips", type=int, default=50)
p.add_argument("--per-ip", type=int, default=3, help="passwords tried from each IP")
p.add_argument("--wordlist", default=str(HERE / "wordlist.txt"))
p.add_argument("--max-seconds", type=float, default=120, help="give up after this long")
p.add_argument("--throttle-threshold", type=float, default=0.9,
               help="a response slower than this (s) counts as throttled")
p.add_argument("--i-own-this-target", action="store_true",
               help="allow a non-localhost URL (only for servers you own)")
args = p.parse_args()

host = urlparse(args.url).hostname
if host not in ("localhost", "127.0.0.1") and not args.i_own_this_target:
    sys.exit(f"Refusing to attack {host}. Only test systems you own (see --i-own-this-target).")

words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
first = ipaddress.ip_address(args.first_ip)
plan = []
for n in range(args.ips):
    ip = str(first + n)
    for k in range(args.per_ip):
        idx = n * args.per_ip + k
        if idx < len(words):
            plan.append((ip, words[idx]))

print(f"Attacking '{args.user}' from {args.ips} IPs x {args.per_ip} passwords "
      f"({len(plan)} attempts, max {args.max_seconds:.0f}s)...\n")

session = requests.Session()
counts = Counter()
throttled = 0
first_throttle = None
max_latency = 0.0
found = None
start = time.monotonic()

for i, (ip, pw) in enumerate(plan, 1):
    if time.monotonic() - start > args.max_seconds:
        print(f"  time limit reached after {i - 1} attempts")
        break
    t0 = time.monotonic()
    try:
        r = session.post(args.url, json={"username": args.user, "password": pw},
                         headers={"X-Sim-IP": ip, "User-Agent": "bforce-distributed-sim/1.0"},
                         timeout=40)
    except requests.RequestException as exc:
        counts["error"] += 1
        print(f"  attempt {i} ({ip}): error {exc}")
        continue
    latency = time.monotonic() - t0
    max_latency = max(max_latency, latency)
    counts[r.status_code] += 1
    if latency >= args.throttle_threshold:
        throttled += 1
        if first_throttle is None:
            first_throttle = (i, time.monotonic() - start)
            print(f">> THROTTLED at attempt {i} ({ip}), {first_throttle[1]:.1f}s after start")
    if r.status_code == 200:
        found = i
        print(f"!! Password FOUND at attempt {i} from {ip}: the attack was NOT slowed enough.")
        break
    if i % 10 == 0:
        print(f"  {i} attempts sent, last response took {latency:.1f}s")

elapsed = time.monotonic() - start
sent = sum(counts.values())
print("\n=== Distributed attack summary ===")
print(f"Attempts sent: {sent} in {elapsed:.1f}s ({sent / max(elapsed, 0.001):.2f}/s)")
print(f"Responses:     {dict(counts)}")
print(f"Throttled:     {throttled} responses (slowest {max_latency:.1f}s)")
if first_throttle:
    print(f"First throttle: attempt {first_throttle[0]} at {first_throttle[1]:.1f}s")
if first_throttle and not found:
    print("PASS: account throttling slowed the attack and the password was not found")
else:
    print("FAIL: " + ("password was found" if found else "no throttling observed"))
    sys.exit(1)
