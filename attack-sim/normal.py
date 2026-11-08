"""BForce AI - normal user simulator.

Real users log in every few seconds; sometimes they mistype first.
Run it during an attack: every login should still succeed, with zero 403s.
Usage:  python attack-sim/normal.py --duration 90
"""
import argparse
import random
import sys
import time

import requests

# Must match DEMO_USERS in login-app/app.py
USERS = [
    ("198.51.100.10", "alice", "Winter2026!"),
    ("198.51.100.11", "bob", "Blue-Harbor-77"),
    ("198.51.100.12", "carol", "maple#Tree42"),
    ("198.51.100.13", "dave", "Quiet-River-9"),
    ("198.51.100.14", "erin", "Lantern_515"),
    ("198.51.100.15", "frank", "Copper$Moon8"),
]

p = argparse.ArgumentParser()
p.add_argument("--url", default="http://localhost:5000/login")
p.add_argument("--duration", type=int, default=90, help="seconds to run")
p.add_argument("--min-gap", type=float, default=1.0)
p.add_argument("--max-gap", type=float, default=4.0)
args = p.parse_args()

session = requests.Session()
stats = {"logins": 0, "success": 0, "typos": 0, "blocked": 0, "errors": 0}


def attempt(ip, user, pw):
    r = session.post(args.url, json={"username": user, "password": pw},
                     headers={"X-Sim-IP": ip, "User-Agent": "Mozilla/5.0 (normal-user-sim)"},
                     timeout=5)
    if r.status_code == 403:
        stats["blocked"] += 1
    return r.status_code


print(f"Normal users logging in for {args.duration}s...\n")
end = time.monotonic() + args.duration
while time.monotonic() < end:
    time.sleep(random.uniform(args.min_gap, args.max_gap))
    ip, user, pw = random.choice(USERS)
    stats["logins"] += 1
    try:
        if random.random() < 0.10:           # 1 in 10: mistype first
            stats["typos"] += 1
            attempt(ip, user, pw + "x")
        code = attempt(ip, user, pw)
    except requests.RequestException as exc:
        stats["errors"] += 1
        print(f"  {user}: error {exc}")
        continue
    if code == 200:
        stats["success"] += 1
        print(f"  {user} ({ip}) logged in OK")
    else:
        print(f"  {user} ({ip}) got HTTP {code}  <-- problem")

print("\n=== Normal user summary ===")
print(stats)
rate = 100 * stats["success"] / max(stats["logins"], 1)
print(f"Success rate: {rate:.1f}%")
if stats["blocked"] == 0 and stats["success"] == stats["logins"]:
    print("PASS: real users were never affected")
else:
    print("FAIL: real users were affected")
    sys.exit(1)
