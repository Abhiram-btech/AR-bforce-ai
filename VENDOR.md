# Vendored CrowdSec

BForce AI runs on its own copy of CrowdSec, built from source. At runtime nothing is downloaded from CrowdSec's servers.

## What we use

| Path | Source | Version |
| --- | --- | --- |
| `vendor/crowdsec` | git submodule, fork https://github.com/Abhiram-btech/crowdsec of https://github.com/crowdsecurity/crowdsec | tag **v1.7.0** |
| `vendor/hub` | git submodule, fork https://github.com/Abhiram-btech/hub of https://github.com/crowdsecurity/hub | default branch, for reference (see below) |

> **Current state:** the forks don't exist yet (the Codespace's GitHub token can't create them), so `.gitmodules` currently points at the **upstream** repos. The code is the same and the tag is the same v1.7.0. Once the forks exist on GitHub, switch to them:
> ```bash
> git submodule set-url vendor/crowdsec https://github.com/Abhiram-btech/crowdsec
> git submodule set-url vendor/hub https://github.com/Abhiram-btech/hub
> git submodule sync && git commit -am "Use our CrowdSec and hub forks" && git push
> ```

`docker-compose.yml` builds `vendor/crowdsec` with CrowdSec's own `Dockerfile` (unchanged) and tags the image `bforce/crowdsec:v1.7.0`.

## Clone / rebuild

```bash
git clone --recurse-submodules https://github.com/Abhiram-btech/AR-bforce-ai
# or, in an existing clone:
git submodule update --init --recursive

docker compose build crowdsec        # compiles CrowdSec from vendor/crowdsec (takes several minutes)
docker compose up -d
```

## How runtime downloads are switched off

The image's entrypoint (`vendor/crowdsec/docker/docker_start.sh`) and `cscli` can contact CrowdSec's servers at startup. Each path is closed:

| What would contact CrowdSec | Where | How it's switched off |
| --- | --- | --- |
| Online API (CAPI) registration, console enroll, signal push, PAPI | entrypoint + LAPI | `DISABLE_ONLINE_API=true` removes `api.server.online_client` |
| `cscli hub upgrade` on every start | entrypoint `run_hub_upgrade_if_from_volume` | `NO_HUB_UPGRADE=true` |
| `cscli hub update` on start (if the index is older than 24 h) | entrypoint `run_hub_update_if_from_volume`, which runs only when `/etc/crowdsec/hub` is in a volume | No volume on `/etc/crowdsec` (the old `crowdsec-config` volume was removed). There is no env var for this. |
| Version check `https://version.crowdsec.net/latest` | `cscli` (`require/branch.go`), whenever `hub_branch` is empty | `cscli.hub_branch: v1.7.0` in `crowdsec/config.yaml.local` |
| Hub downloads from `https://cdn-hub.crowdsec.net` | `cscli` | `cscli.__hub_url_template__` in `crowdsec/config.yaml.local` points at a dead local port, so any hub download fails instead of fetching |
| `PARSERS=...` hub installs | entrypoint | `PARSERS` is not set. Our raw-stage parser is the local `crowdsec/parsers/bforce-raw.yaml`, because `crowdsecurity/non-syslog` does not exist in the hub (neither upstream nor in the v1.7.0 index). |

`crowdsec/config.yaml.local` is merged over the image's `config.yaml` by CrowdSec itself (the `.local` override mechanism).

**Note: `docker compose build` does use the internet.** CrowdSec's Dockerfile downloads Go modules, re2 and yq from GitHub, and Alpine packages. Its build stage also runs `cscli hub update --with-content` and installs `crowdsecurity/linux` and `crowdsecurity/whitelists` from CrowdSec's hub CDN. Those items are baked into the image, so the container doesn't need to fetch them later. `vendor/hub` is not used by the build yet. Making the build install hub items from `vendor/hub` instead of the CDN would need a change to the Dockerfile.

## Pulling updates from the original project (optional)

We stay on v1.7.0 until we choose to upgrade. To move to a newer release later:

```bash
cd vendor/crowdsec
git remote add upstream https://github.com/crowdsecurity/crowdsec   # once
git fetch upstream --tags
git checkout v1.X.Y                                                 # the release you want
git push origin v1.X.Y                                              # keep the tag in our fork too
cd ../..
```

Then update `v1.7.0` in `docker-compose.yml` (`BUILD_VERSION` and `image`) and in `crowdsec/config.yaml.local` (`hub_branch`). Rebuild, run the Step 1 and Step 2 tests (normal.py must stay at 100%), and commit the new submodule pointer:

```bash
docker compose build crowdsec && docker compose up -d
git add vendor/crowdsec docker-compose.yml crowdsec/config.yaml.local
git commit -m "Upgrade vendored CrowdSec to v1.X.Y"
```

For the hub, the process is the same: `cd vendor/hub && git remote add upstream https://github.com/crowdsecurity/hub && git fetch upstream && git merge upstream/master`. Commit the new submodule pointer afterwards.

Also re-check `docker/docker_start.sh` after any upgrade: new versions may add startup steps that contact CrowdSec's servers.

## License

CrowdSec is MIT licensed. Its license is kept unchanged in `vendor/crowdsec/LICENSE`. The hub's license is in `vendor/hub/LICENSE`.
