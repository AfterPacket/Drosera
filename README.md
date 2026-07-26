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

## Requirements

Ubuntu 22.04/24.04, Docker 24+ with Compose v2, 2 vCPU / 4 GB / 40 GB, a domain
on Cloudflare, and a VPS dedicated entirely to this.

## Verification status

The code has not been executed. It was written and reviewed statically; the
build, container startup, and end-to-end behaviour still need to be confirmed on
the VPS. Work through `deploy/README.md` §9 and §12 before relying on it.
