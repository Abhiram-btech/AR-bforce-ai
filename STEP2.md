# BForce AI – Step 2: attackers who spread out their attempts

Step 1 catches one IP hammering one account. Step 2 adds three slower or wider attack patterns, plus a defence for each. All Step 1 behaviour still works (`attack.py` is banned in about 2 s).

## What was added

| File | What it does |
| --- | --- |
| `crowdsec/scenarios/login-spray.yaml` | `bforce/login-spray`: one IP failing on **6+ different usernames** (distinct `target_user`, capacity 5, leak 30 s) leads to a ban. |
| `crowdsec/scenarios/login-slow.yaml` | `bforce/login-slow`: like `login-bf` but capacity 30 and leak 2 min, so it catches an IP that paces itself under `login-bf`. |
| `login-app/app.py` | **Account throttling.** It counts failures per username over 15 minutes. Once there are 5 or more, coming from at least 3 different IPs, every login for that username is delayed by 1 s, 2 s, 4 s … up to a cap of 30 s. A successful login resets the counter. Delayed failures are logged as `"result": "throttled"` with a `"delay"` field. It never bans and never locks the account. |
| `attack-sim/spray.py` | 203.0.113.20 tries 2 common passwords on 50 usernames (password-major order). `--gap` paces it. |
| `attack-sim/distributed.py` | 50 IPs (203.0.113.100–149), 3 passwords each, all on `alice`. It stops after `--max-seconds` (default 120). |
| `attack-sim/slow.py` | 203.0.113.30 sends one wrong password every 5 s, for up to 10 minutes. |
| `attack-sim/normal.py` | Request timeout raised to 40 s, so throttled real users count as delayed, not failed. |
| `docker-compose.yml` | Mounts the two new scenarios. |
| `crowdsec/scenarios/login-bf.yaml` | Filter now matches `fail` **and** `throttled`, so delayed failures still count towards a ban. |

## How to run the tests

```bash
docker compose up -d --build
docker exec crowdsec cscli scenarios list | grep bforce    # login-bf, login-spray, login-slow
```

Run each attack on its own, with `normal.py` in a second terminal started a few seconds before it:

```bash
# Terminal 1 (use --duration 200 for slow.py)
python attack-sim/normal.py --duration 60

# Terminal 2: one of these
python attack-sim/attack.py          # Step 1: banned by login-bf
python attack-sim/spray.py           # banned (login-spray + login-bf)
python attack-sim/spray.py --gap 2   # paced spray: banned by login-spray alone
python attack-sim/distributed.py     # throttled (no ban), runs 120 s
python attack-sim/slow.py            # banned by login-slow after about 2.5-3 min

docker exec crowdsec cscli alerts list
docker exec crowdsec cscli decisions list
```

Reset between runs:
```bash
docker exec crowdsec cscli decisions delete --all
docker compose restart crowdsec login-app   # also clears leaky buckets and throttle counters
```

Each attack simulator prints `PASS`/`FAIL`, and `normal.py` must print `PASS: real users were never affected`.

## Results (2026-11-08)

| Attack | Caught by | Time to catch | normal.py |
| --- | --- | --- | --- |
| Single-IP brute force (`attack.py`) | CrowdSec `login-bf` ban | 2.0 s (attempt 17) | 100% (27/27) |
| Password spray, full speed (`spray.py`) | `login-spray` + `login-bf` ban | 2.0 s (attempt 17) | 100% (20/20) |
| Password spray, 1 per 2 s (`spray.py --gap 2`) | `login-spray` ban | 12.7 s (attempt 7) | 100% (15/15) |
| Distributed, 50 IPs on alice (`distributed.py`) | Account throttling (no ban) | throttled from attempt 8 (4.9 s); slowed to 28 attempts in 120 s, password not found | 100% (31/31) |
| Low-and-slow, 1 per 5 s (`slow.py`) | CrowdSec `login-slow` ban | 163.9 s (attempt 33) | 100% (78/78) |

## Limitations found

1. **Throttling only starts once failures come from 3 or more IPs** (`THROTTLE_MIN_IPS`, default 3). With the spec's plain "5 failures from any IP" rule, the Step 1 single-IP attack got throttled before CrowdSec saw enough failures. That slowed the ban from 2 s to 41 s and broke the Step 1 checklist. CrowdSec already bans single-IP attacks quickly, so the throttle now targets the distributed pattern only.
2. **The real owner of an attacked account is delayed too.** During `distributed.py`, real `alice` logins took up to 30 s (still successful, within normal.py's 40 s timeout). Every real successful login also resets the counter, which gives the attacker 5 fast attempts again.
3. **Throttling works per request, not per attacker.** An attacker sending many requests in parallel is not slowed in total, and each delayed request ties up a Flask thread while it sleeps. Concurrent requests may all see the same failure count.
4. **Throttle state is in memory.** It is lost when the login app restarts and not shared between several app instances. It tracks at most 10,000 usernames.
5. **Distributed spraying is not caught.** Many IPs × many usernames keeps every IP and every username under all thresholds.
6. **Slower attackers slip through.** An IP failing less than about once per 2 minutes never fills `login-slow`.
7. **At full speed a spray also trips `login-bf`.** The spray scenario's own value only shows when the attacker paces itself (see `--gap 2`).
8. **Ban length is CrowdSec's default (4 h).** `blackhole` only stops repeat alerts for the same IP; it is not the ban duration.
9. **About 2 s of block lag** comes from the login app's 2 s decision cache, so a few attempts get through after the ban.
10. **`decisions delete --all` doesn't empty leaky buckets.** Restart CrowdSec between tests for clean timings; otherwise an earlier run's failures can trigger a ban sooner.
