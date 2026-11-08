# BForce AI – project rules

## Project
BForce AI is real-time brute-force login detection. The loop is **Watch -> Detect -> Decide -> Act**.

## Stack
- `login-app/`: Flask login app. It is the sensor (writes JSON lines to `auth.log`) and the bouncer (asks CrowdSec before checking a password).
- `crowdsec/`: CrowdSec is the detector (acquisition, parsers, scenarios).
- `docker-compose.yml`: runs the stack with Docker Compose.
- `attack-sim/`: Python simulators (`normal.py` for real users, the rest for attacks).

## Rules
1. **Golden rule: real users must never be blocked.** Every change must keep `normal.py` at 100% success.
2. Use the smallest response that is safe: delay or throttle before banning. Never lock accounts.
3. Attack simulators only target localhost. Never add code that attacks external hosts.
4. Never commit secrets. `.env` stays in `.gitignore`. `TEST_MODE` / `X-Sim-IP` is for testing only and must never be enabled in production.
5. After every change: run the simulators (`normal.py` at the same time as the attack simulators), report the results, then commit with a clear message and push.

## Useful commands
```bash
docker compose up -d --build
docker exec crowdsec cscli decisions list
docker exec crowdsec cscli decisions delete --all   # reset between test runs
python attack-sim/normal.py --duration 60           # run at the same time as an attack simulator
```
