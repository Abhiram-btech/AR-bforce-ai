# BForce AI – Step 1: run the full loop

## 1. One-time setup

```bash
cp .env.example .env
sed -i "s/replace-me/$(openssl rand -hex 24)/" .env   # creates your secret bouncer key
pip install -r attack-sim/requirements.txt
```

`.env` is in `.gitignore`, so the key is never committed. Your friend makes their own `.env` the same way.

## 2. Start the stack

```bash
docker compose up -d --build
docker compose ps                  # both containers should be "running"
docker compose logs -f crowdsec    # Ctrl+C to stop watching
```

Open the **Ports** tab in the Codespace and click the globe next to port 5000 to see the login page.
Try `alice` / `Winter2026!` (works) and a wrong password (fails).

Check CrowdSec loaded your files:

```bash
docker exec crowdsec cscli parsers list | grep bforce
docker exec crowdsec cscli scenarios list | grep bforce
docker exec crowdsec cscli bouncers list          # should show "loginapp"
```

## 3. Run the test (two terminals)

Terminal 1 – real users:
```bash
python attack-sim/normal.py --duration 90
```

Terminal 2 – start this a few seconds later:
```bash
python attack-sim/attack.py
```

Then check:
```bash
docker exec crowdsec cscli alerts list
docker exec crowdsec cscli decisions list
```

## 4. Step 1 checklist

- [ ] attack.py prints `BLOCKED` and `PASS` (blocked within 10 s)
- [ ] attack.py never prints `Password FOUND` (alice's password is #150 in the wordlist)
- [ ] `cscli decisions list` shows 203.0.113.7 banned
- [ ] normal.py prints `PASS: real users were never affected`
- [ ] Ban expiry: `docker exec crowdsec cscli decisions add --ip 203.0.113.99 --duration 1m`, then run
      `python attack-sim/attack.py --ip 203.0.113.99`; it is blocked now and allowed again after 1 minute

## Reset between test runs

```bash
docker exec crowdsec cscli decisions delete --all
```

## If something doesn't work

| Symptom | Check |
| --- | --- |
| attack never blocked | `docker exec crowdsec cscli metrics` – are lines read and parsed? |
| lines read but not parsed | `docker exec crowdsec cscli explain --file /logs/auth.log --type bforce` shows where they fail |
| parsed but no alert | `docker exec crowdsec cscli scenarios list` – is `bforce/login-bf` enabled? |
| alert but no 403 | `docker compose logs login-app` – look for "CrowdSec check failed" (wrong key in `.env`?) |
| crowdsec won't start | `docker compose logs crowdsec` – paste the error to Claude |

Then commit:
```bash
git add . && git commit -m "Step 1: login app + CrowdSec loop" && git push
```
