"""BForce AI - Step 1 fake login app.

It is both the SENSOR (writes one JSON line per login attempt to auth.log)
and the BOUNCER (asks CrowdSec whether an IP is banned before checking a password).
Demo only: the users and passwords below are fake.
"""
import ipaddress
import json
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

LOG_PATH = os.environ.get("LOG_PATH", "/logs/auth.log")
TEST_MODE = os.environ.get("TEST_MODE") == "1"
CROWDSEC_URL = os.environ.get("CROWDSEC_URL", "http://crowdsec:8080")
BOUNCER_KEY = os.environ.get("CROWDSEC_BOUNCER_KEY", "")
CACHE_SECONDS = 2.0  # how long a ban/no-ban answer is reused

# Account throttling (Step 2): slows down attacks on ONE account from MANY IPs.
# It only delays responses; it never bans and never locks the account.
THROTTLE_WINDOW = 15 * 60   # count failures per username over the last 15 minutes
THROTTLE_AFTER = 5          # start delaying once this many failures are in the window
THROTTLE_MAX_DELAY = 30.0   # seconds; 1s, 2s, 4s, ... capped here
# Only throttle when the failures come from at least this many DIFFERENT IPs. Single-IP attacks
# are left to CrowdSec, which bans them in ~2s; throttling them would slow the ban down.
THROTTLE_MIN_IPS = int(os.environ.get("THROTTLE_MIN_IPS", "3"))
THROTTLE_MAX_USERS = 10_000  # usernames are attacker-controlled: bound memory

# Fake demo users. Passwords are hashed at startup; never store plain text in real apps.
DEMO_USERS = {
    "alice": "Winter2026!",
    "bob": "Blue-Harbor-77",
    "carol": "maple#Tree42",
    "dave": "Quiet-River-9",
    "erin": "Lantern_515",
    "frank": "Copper$Moon8",
}
USERS = {u: generate_password_hash(p) for u, p in DEMO_USERS.items()}
DUMMY_HASH = generate_password_hash("not-a-real-password")  # equal timing for unknown users

app = Flask(__name__)
_log_lock = threading.Lock()
_cache = {}
_cache_lock = threading.Lock()
_fails = defaultdict(deque)  # username -> deque of (monotonic time, ip) of recent failures
_fails_lock = threading.Lock()


def client_ip():
    """Real client IP. In TEST_MODE only, simulators may fake it with X-Sim-IP."""
    if TEST_MODE:
        sim = request.headers.get("X-Sim-IP", "").strip()
        if sim:
            try:
                return str(ipaddress.ip_address(sim))
            except ValueError:
                pass
    return request.remote_addr or "0.0.0.0"


def log_attempt(ip, user, result, delay=0.0):
    line = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "user": (user or "")[:64],  # attacker-controlled: keep it short
        "result": result,           # success | fail | throttled (failed + delayed) | blocked
        "ua": (request.headers.get("User-Agent") or "")[:128],
    }
    if delay:
        line["delay"] = round(delay, 1)
    with _log_lock, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


def is_banned(ip):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(ip)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    try:
        r = requests.get(
            f"{CROWDSEC_URL}/v1/decisions",
            params={"ip": ip},
            headers={"X-Api-Key": BOUNCER_KEY},
            timeout=1.0,
        )
        r.raise_for_status()
        decisions = r.json() or []  # CrowdSec returns null when there is no decision
        banned = any(d.get("type") == "ban" for d in decisions)
    except Exception as exc:  # noqa: BLE001
        # FAIL OPEN: if CrowdSec is down, let users log in rather than locking everyone out.
        app.logger.warning("CrowdSec check failed (%s); failing open", exc)
        return False
    with _cache_lock:
        _cache[ip] = (now, banned)
    return banned


def _prune(q, now):
    while q and now - q[0][0] > THROTTLE_WINDOW:
        q.popleft()


def throttle_delay(user):
    """Seconds to delay a login for this username (0 = no delay)."""
    now = time.monotonic()
    with _fails_lock:
        q = _fails.get(user)
        if not q:
            return 0.0
        _prune(q, now)
        n = len(q)
        if n < THROTTLE_AFTER or len({ip for _, ip in q}) < THROTTLE_MIN_IPS:
            return 0.0
    return min(THROTTLE_MAX_DELAY, 2.0 ** (n - THROTTLE_AFTER))


def record_failure(user, ip):
    now = time.monotonic()
    with _fails_lock:
        if user not in _fails and len(_fails) >= THROTTLE_MAX_USERS:
            for u in [u for u, q in _fails.items() if not q or now - q[-1][0] > THROTTLE_WINDOW]:
                del _fails[u]
            if len(_fails) >= THROTTLE_MAX_USERS:
                return  # still full of active entries: skip rather than grow without limit
        _fails[user].append((now, ip))
        _prune(_fails[user], now)


def reset_failures(user):
    with _fails_lock:
        _fails.pop(user, None)


PAGE = """<!doctype html><title>BForce demo login</title>
<style>body{font-family:system-ui,sans-serif;max-width:360px;margin:60px auto}
input,button{display:block;width:100%;margin:8px 0;padding:8px;font-size:15px}</style>
<h2>Demo login</h2>{% if msg %}<p><b>{{ msg }}</b></p>{% endif %}
<form method="post" action="/login">
<input name="username" placeholder="username" autocomplete="username">
<input name="password" type="password" placeholder="password" autocomplete="current-password">
<button>Log in</button></form>"""


def reply(ok, status, msg):
    if request.is_json:
        return jsonify({"ok": ok, "message": msg}), status
    return render_template_string(PAGE, msg=msg), status


@app.get("/")
def index():
    return render_template_string(PAGE, msg=None)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login():
    data = request.get_json(silent=True) if request.is_json else request.form
    data = data or {}
    user = str(data.get("username", ""))
    password = str(data.get("password", ""))
    ip = client_ip()

    if is_banned(ip):
        log_attempt(ip, user, "blocked")
        return reply(False, 403, "Too many attempts. Try again later.")

    delay = throttle_delay(user)  # same for known and unknown usernames
    if delay:
        time.sleep(delay)

    stored = USERS.get(user, DUMMY_HASH)
    ok = check_password_hash(stored, password) and user in USERS
    if ok:
        reset_failures(user)
        log_attempt(ip, user, "success", delay)
        return reply(True, 200, f"Welcome, {user}!")
    record_failure(user, ip)
    log_attempt(ip, user, "throttled" if delay else "fail", delay)
    return reply(False, 401, "Wrong username or password.")  # same message for unknown users


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "a").close()  # create the log so CrowdSec can watch it
    app.run(host="0.0.0.0", port=5000, threaded=True)
