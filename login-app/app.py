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
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

LOG_PATH = os.environ.get("LOG_PATH", "/logs/auth.log")
TEST_MODE = os.environ.get("TEST_MODE") == "1"
CROWDSEC_URL = os.environ.get("CROWDSEC_URL", "http://crowdsec:8080")
BOUNCER_KEY = os.environ.get("CROWDSEC_BOUNCER_KEY", "")
CACHE_SECONDS = 2.0  # how long a ban/no-ban answer is reused

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


def log_attempt(ip, user, result):
    line = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "user": (user or "")[:64],  # attacker-controlled: keep it short
        "result": result,           # success | fail | blocked
        "ua": (request.headers.get("User-Agent") or "")[:128],
    }
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

    stored = USERS.get(user, DUMMY_HASH)
    ok = check_password_hash(stored, password) and user in USERS
    log_attempt(ip, user, "success" if ok else "fail")
    if ok:
        return reply(True, 200, f"Welcome, {user}!")
    return reply(False, 401, "Wrong username or password.")  # same message for unknown users


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "a").close()  # create the log so CrowdSec can watch it
    app.run(host="0.0.0.0", port=5000, threaded=True)
