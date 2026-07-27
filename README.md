# Drosera

A zero-trust honeypot appliance. It presents a convincing small-business website
to the public, runs seven emulated protocol services underneath, wastes attacker
and bot resources with tarpits, records every session as evidence, renders those
sessions to video and sends them to you, and exposes it all through a separately
secured operator dashboard.

Nothing an attacker sends is ever executed, stored as code, or forwarded
anywhere. See [`AUTHORIZATION.md`](AUTHORIZATION.md) for the legal and ethical
basis, and for the design safeguards that make it non-weaponizable.

```
Internet
   │
   ├─ :80/:443 ─► nginx ─┬─► fake business site (Meridian Digital Solutions)
   │                     ├─► webshell emulator  (/wp-admin/admin-ajax.php)
   │                     ├─► crawler trap       (/blog/…, effectively infinite)
   │                     └─► scanner-path traps (.env, wp-config.php, backup.sql…)
   │
   ├─ :22   ─► fake sshd     (+ endlessh tarpit, SFTP sink, session recording)
   ├─ :21   ─► fake ftpd
   ├─ :23   ─► fake telnetd
   ├─ :25   ─► fake smtpd    (advertises an open relay, delivers nothing)
   ├─ :3306 ─► fake mysqld   (protocol v10 wire format)
   ├─ :445  ─► fake smbd     (SMB2, captures NTLMv2 responses)
   ├─ :139  ─► fake smbd     (NetBIOS)
   └─ :3389 ─► fake rdpd     (X.224)

Operator only, via SSH tunnel:
   ├─ 127.0.0.1:8443 ─► dashboard (separate app, separate Redis, password + TOTP)
   └─ 127.0.0.1:5601 ─► Kibana    (own internal network, no honeypot access)

Session camera (the only container with egress, on no other network):
   storage/sessions/*.cast ─► session-cam ─► Telegram / email / dashboard

Analytics (internal only, fed off the volume rather than over the network):
   storage/logs/*.jsonl ─► elastic-shipper ─► Elasticsearch ─► Kibana
```

## Core principle

**No legitimate traffic should ever touch this machine.** Every connection to
any port is, by construction, an alert. That premise is what lets the system be
this aggressive — and it is why you must not co-host anything real on the box.

## How it responds

Three tiers, driven by a cumulative per-IP score:

| Tier | Trigger | Response |
|---|---|---|
| 1 | Unknown visitor | Serve the convincing fake site. Log silently |
| 2 | Confirmed scanner (tool in User-Agent, or a known probe path) | Engage the tarpit: claim a 10 MB body, then trickle bytes at ~3 KB/s until they give up |
| 3 | Score ≥ 35 | Ban. Redirect to a rickroll, and write a fail2ban line that firewalls them at the host |

Scores accumulate across *every* service. An attacker who probes the web shell
and then tries SSH is one profile, with one consistent fake machine identity —
same hostname, same kernel, same users, same filesystem. Redis is the single
source of truth shared by the PHP engine and the Python services.

## Zero-trust guarantees

- No `exec`/`system`/`shell_exec`/`popen`/`eval` on anything, in any language
- No attacker string ever reaches a real path, shell argument, or DB connection
- Uploads are hashed for evidence, then `unlink`ed immediately
- All simulated state lives in Redis; the only disk writes are appends to fixed
  paths under `storage/`, which nginx never serves
- Every container: non-root (UID 1000), read-only rootfs, all capabilities
  dropped, `no-new-privileges`, setuid binaries stripped, memory and PID capped
- Every writable path — tmpfs and the captured-data mount — is
  `noexec,nosuid,nodev`, so there is nowhere to stage or run a payload
- **Both Docker networks are `internal: true`** — no container can make an
  outbound connection, so the box cannot be used as a pivot or a relay

Together those mean code execution inside a container is a dead end: nothing to
write to, nothing to execute from, nothing to fetch. See `deploy/README.md` §17
for the escape threat model and the commands to verify each control.

## Fail-safes

Built to survive unattended:

- Writes stop before the disk fills; a cron watchdog prunes and restarts
- Tarpit concurrency is capped below `pm.max_children`, so tarpits can never
  starve the site of its own workers
- Every tarpit has a hard deadline; the SSH honeypot sheds load past a limit
- Redis is memory-capped with LRU eviction
- Container logs are size-capped
- Unhealthy or dead containers are restarted automatically

## Quick start

```bash
git clone <your-repo> /opt/drosera && cd /opt/drosera
sudo ADMIN_IP=$(curl -s ifconfig.me) ./deploy/bootstrap.sh
cp .env.example .env && nano .env          # set DOMAIN
# install certs/origin.pem + certs/origin.key from Cloudflare
docker compose run --rm admin-dashboard python3 setup.py
sudo ADMIN_IP=$(curl -s ifconfig.me) ./ssh-real/cutover.sh
docker compose up -d --build
```

Full walkthrough: [`deploy/README.md`](deploy/README.md).
Condensed path: [`QUICKSTART.md`](QUICKSTART.md).

## Dashboard

Reachable only over an SSH tunnel — it is never proxied by nginx and never
exposed to the internet.

```bash
ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@your-vps
```

Password **and** TOTP are both required; the session is created only after the
TOTP step succeeds. Pages: live feed, per-IP attacker profiles with session
replay, evidence log, charts, audit trail, settings.

Evidence export produces a ZIP with the event log, identity record, asciinema
recordings, an HTML report, and a suggested fail2ban line.

## Layout

```
shared/           Python: identity, scoring, alerting, tarpit, fake shell
web/              nginx + PHP-FPM, public site, webshell, tarpit engine
{ssh,ftp,telnet,smtp,mysql,smb,rdp}-honey/   protocol emulators
session-cam/      renders sessions to video and delivers them
elastic/          ships events to Elasticsearch; Kibana stats
admin-dashboard/  Flask operator UI
nginx/            site config
fail2ban/         filter, jail, ufw action
deploy/           bootstrap, watchdog, logrotate, deployment guide
ssh-real/         SSH port cutover with deadman-switch rollback
```

See [`MANIFEST.md`](MANIFEST.md) for a file-by-file description.

## Running it

```bash
docker compose up -d --build            # honeypot, dashboard, session camera
docker compose ps
./deploy/preflight.sh                   # static checks, safe any time
./deploy/smoke-test.sh                  # ports, render, containment
```

| Task | Command |
|---|---|
| Small VPS (2–4 GB) | `docker compose -f docker-compose.yml -f deploy/compose.small.yml up -d` |
| With Elasticsearch | `docker compose --profile elastic up -d` |
| With automatic TLS | `docker compose --profile letsencrypt up -d` |
| Live event feed | `tail -f storage/logs/$(date -u +%F).jsonl` |
| Bans as they fire | `tail -f storage/evidence/fail2ban.log` |
| Wipe and re-baseline | `./deploy/reset-data.sh --yes` |
| Dashboard | `ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@vps` → <http://127.0.0.1:8443> |

**A profile flag is part of the service's identity.** `--profile elastic` /
`--profile letsencrypt` must be repeated on every `up`, `down`, `logs` and `ps`
touching those containers, or Compose behaves as though they do not exist.

## Troubleshooting

Everything below was hit during a real first deployment.

**Honeypot ports are not listening.** `docker inspect <c> --format '{{json
.NetworkSettings.Ports}}'` returns `null` while `.HostConfig.PortBindings` looks
correct. Docker does not install DNAT rules for published ports on an
`internal: true` network — the config is accepted and silently does nothing.
`honeypot-internal` is therefore a normal bridge, and egress is denied by
DOCKER-USER rules that `bootstrap.sh` installs. Re-run bootstrap after any pull
that touches it.

**SSH won't move off port 22.** `sshd -T` reports both ports, `ss` shows only
one, and the listener has backlog 4096 rather than 128. That is systemd's
socket, not sshd: Ubuntu 24.04+ uses socket activation, under which `Port`
directives in `sshd_config` are ignored entirely.

```bash
sudo systemctl disable --now ssh.socket && sudo systemctl mask ssh.socket
sudo systemctl enable --now ssh.service
```

`mask` matters — `disable` alone lets a package upgrade bring it back.

**Locked out after running bootstrap.** `ADMIN_IP=$(curl -s ifconfig.me)`
executed *on the VPS* resolves to the VPS's own address, so ufw allows 2222 from
the box and nobody else. Symptom is a connection timeout (a drop) rather than a
refusal. Get the value from your own machine, or `echo "${SSH_CLIENT%% *}"` on
an existing session.

**Dashboard returns "Forbidden".** `allowed_ips` defaults to `127.0.0.1`, but
docker-proxy rewrites the source to the bridge gateway, so Flask sees
`172.x.x.x`. Add `"172.*"` to `admin-dashboard/config/admin-config.json`. Not a
loosening — the port is bound to loopback on the host regardless.

**`hp-web` restart-loops.** Two causes, both about the read-only rootfs:
php-fpm's *global* config logging to `/var/log/php8.1-fpm.log`, and `/run`
mounting root-owned when `mode=1777` is missing. Both are fixed in-tree; check
`docker logs hp-web` for which one you are seeing.

**nginx claims to load the certificate then dies.** The entrypoint's existence
check passes on a file it cannot read — `stat` needs no read permission. A
certificate created with `sudo` is `root:root 0600` and unreadable to UID 1000:

```bash
sudo chown 1000:1000 certs/origin.pem certs/origin.key
```

**Scripts are "Permission denied" after `git pull`.** Exec bits are now set in
the git index, so this is fixed — but a local `chmod +x` is itself a tracked
change and will block the next merge. `git checkout -- .` before pulling.

**`.env` changes have no effect.** `docker compose restart` reuses the existing
container environment. Use `up -d` (add `--force-recreate` if in doubt), and
confirm with `docker compose config | grep VAR`.

**Certificate stays on the staging CA.** `--keep-until-expiring` sees a valid
certificate and declines to reissue, even though nothing trusts it. Set
`LETSENCRYPT_STAGING=false`, verify with `docker compose config`, then
`certbot delete --cert-name <domain>` before recreating.

**Few session recordings, and short ones.** A tarpitted IP never reaches the
interactive handler, which is the only place a recorder is created — so a low
`HONEYPOT_TARPIT_THRESHOLD` means you tarpit exactly the attackers worth
watching. Raise it to ~20. Most short clips are genuine: credential-validation
bots log in, read the prompt, and leave.

**Dashboard charts or playback blank.** Both are self-hosted; nothing loads from
a CDN. A blank page after an update is a stale cached script — hard-refresh
(Ctrl+Shift+R).

## Requirements

Ubuntu 22.04/24.04, Docker 24+ with Compose v2, 2 vCPU / 4 GB / 40 GB, a domain
on Cloudflare, and a VPS dedicated entirely to this.

## Verification status

The code has not been executed. It was written and reviewed statically; the
build, container startup, and end-to-end behaviour still need to be confirmed on
the VPS. Work through `deploy/README.md` §9 and §12 before relying on it.
