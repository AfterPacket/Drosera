# Drosera

A zero-trust honeypot appliance. It presents a convincing small-business website
to the public, runs seven emulated protocol services underneath, wastes attacker
and bot resources with tarpits, records every session as evidence, renders those
sessions to video and sends them to you, and exposes it all through a separately
secured operator dashboard.

Nothing an attacker sends is ever executed, stored as code, or forwarded
anywhere. See [`AUTHORIZATION.md`](AUTHORIZATION.md) for the legal and ethical
basis, and for the design safeguards that make it non-weaponizable.

Built by [Digital Systems LLC](https://digitalsystems.cc) /
[Afterpacket](https://github.com/afterpacket).

```
Internet
   │
   ├─ :80/:443 ─► nginx ─┬─► fake business site (named by your persona)
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

## The session camera

Every text protocol is recorded as an [asciicast](https://docs.asciinema.org)
covering the **whole connection** — the login attempt, the credentials, the
shell if they open one, until they disconnect. SSH, telnet, FTP, SMTP, MySQL
and the web shell all record; SMB and RDP do not, being binary protocols with
no terminal to replay.

`session-cam` then renders finished recordings to video with a
security-camera overlay — record dot, address, service, clock, running score,
tool, and the fake hostname they were shown — and delivers them:

| Where | What arrives |
|---|---|
| Telegram | The clip, captioned with IP, score, tool and credentials tried |
| Email | Same, as an attachment |
| Dashboard | Inline playback plus the raw `.cast` |
| Webhook | Metadata only |

It also tails the event log and sends a **live alert the moment someone opens a
shell**, rather than waiting for the clip. That alerting lives in `session-cam`
because it is the only container with internet access — the honeypots have
none, by design, so anything they tried to send would go nowhere.

Recording is deliberately generous and delivery is gated: clips are only sent
past a score, content and frame floor, so a port scan does not become a
notification.

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
- **No egress from the honeypot** — enforced by DOCKER-USER firewall rules that
  drop anything the honeypot subnet originates outbound, while allowing replies
  to inbound connections. Not by `internal: true`: Docker refuses to publish
  ports on an internal network, which would leave every honeypot unreachable.
  `deploy/smoke-test.sh` asserts this in both directions rather than trusting it
- **One container has internet access** — `session-cam`, which delivers clips
  and alerts. It is on no other network and receives recordings through the
  storage volume, so a compromised honeypot gains no route out through it, and a
  compromised camera gains no route in

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

## Deploying to a VPS

Full walkthrough in [`deploy/README.md`](deploy/README.md). The spine:

```bash
# 1. base packages
sudo apt-get update && sudo apt-get install -y ufw fail2ban logrotate git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && exit          # log back in

# 2. clone
sudo git clone <your-repo> /opt/drosera
sudo chown -R $USER:$USER /opt/drosera && cd /opt/drosera

# 3. host hardening. ADMIN_IP is YOUR address, not the VPS's -- getting this
#    wrong is the most common way to lock yourself out
sudo ADMIN_IP=203.0.113.10 ./deploy/bootstrap.sh

# 4. configure
cp .env.example .env && nano .env              # DOMAIN, WEBSHELL_ACTION

# 5. TLS: either drop a Cloudflare Origin Certificate into certs/,
#    or use the letsencrypt profile (§13 of deploy/README.md)
sudo chown 1000:1000 certs/origin.pem certs/origin.key

# 6. dashboard account -- scan the TOTP QR before dismissing it
docker compose run --rm admin-dashboard python3 setup.py

# 7. move real SSH off port 22 BEFORE starting, using the deadman switch
sudo ADMIN_IP=203.0.113.10 ./ssh-real/cutover.sh

# 8. launch
./deploy/preflight.sh
docker compose up -d --build
./deploy/smoke-test.sh
```

Sizing: **2 vCPU / 4 GB / 40 GB** runs the honeypot, tarpits, camera and
dashboard comfortably. Elasticsearch needs ~2.5 GB more — see below.

| Task | Command |
|---|---|
| Small VPS (2–4 GB) | `docker compose -f docker-compose.yml -f deploy/compose.small.yml up -d` |
| With Elasticsearch | `docker compose --profile elastic up -d` |
| With automatic TLS | `docker compose --profile letsencrypt up -d` |
| Refresh GeoIP | `./deploy/update-geoip.sh` |
| Live event feed | `tail -f storage/logs/$(date -u +%F).jsonl` |
| Bans as they fire | `tail -f storage/evidence/fail2ban.log` |
| Wipe and re-baseline | `./deploy/reset-data.sh --yes` |
| Dashboard | `ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@vps` → <http://127.0.0.1:8443> |

### Two rules that will save you an hour

**`restart` is almost never what you want.** Only `shared/` is bind-mounted.
Every service's own code is copied into its image at build time, so a change to
`ssh-honey/`, `telnet-honey/`, `web/`, `session-cam/`, `elastic/` or
`admin-dashboard/` needs `up -d --build`. A plain `restart` silently reuses the
old code, and the symptom is a fix that appears not to work.

Likewise `restart` does not re-read `.env` — use `up -d` for configuration
changes, and confirm with `docker compose config | grep VAR`.

**A profile flag is part of the service's identity.** `--profile elastic` /
`--profile letsencrypt` must be repeated on every `up`, `down`, `logs` and `ps`
touching those containers, or Compose behaves as though they do not exist.

## Optional extras

**Persona** — do this before going live. The engine is public, so every
observable constant shipped as source is a fingerprint: the SSH version string,
the hostname and kernel pools, the shell history, the company name on the
website, even the byte sizes in `ls -la`. Anyone with this repository can
compare a live host against the defaults and identify it in a few lines — which
is exactly why stock Cowrie is trivially detected.

```bash
./deploy/generate-persona.sh
docker compose up -d
```

That writes a randomised, gitignored `persona/persona.json` covering both
halves of the machine — `shared/persona.py` for the protocol honeypots,
`web/lib/persona.php` for the website — so the fake shell and the fake business
site tell one consistent story, and two deployments of the same release are two
different machines. `preflight.sh` warns while you are still running the
published defaults.

It also generates your **honeytokens**: the database password, API key and AWS
key ID planted in the fake `.env`, `wp-config.php` and the homepage comments.
Nothing accepts them, so if one surfaces in a credential-stuffing attempt or a
paste dump, you know which box it was scraped from — an inference that only
works while the values are yours alone.

Keep a backup alongside your `.env`. An attacker who saw one machine last week
and a different one on the same address this week has learnt something.

**Payload capture** — dropped files are quarantined in `storage/loot/`, named by
SHA-256, mode `0400`, on no PATH and under no document root. Nothing in the
honeypot opens, unpacks or runs them; the filename is a hash, so an attacker
never influences a path. Both drop routes are covered: SFTP uploads, and shell
writes (a base64 blob piped through `base64 -d` never touches SFTP, so it is
often the only copy you get).

The `intel` container looks each one up on VirusTotal and alerts on hits. It
runs on `cam-egress` — the honeypots have no outbound route and cannot do this
themselves — and it has no listening ports, so neither side's compromise
reaches the other.

**It sends a hash, never the file.** That distinction is worth understanding
before you change it: VirusTotal distributes submitted samples to its paying
customers, and that market includes the people who write the malware, who
routinely monitor VT for their own payloads. Uploading a targeted implant tells
its operator it was caught and roughly when, can publish whatever the binary
embeds, and burns the visibility you were collecting. For commodity botnet junk
none of that matters and the hash is already known. Submit by hand if and when
you have decided it is safe.

An "unknown to VirusTotal" verdict is the interesting one, not the boring one —
nobody has submitted it, which for a live drop means new or targeted.

Detonation is deliberately not here. Copy the sample to a machine you are
willing to lose.

**Scan-back** — `nmap`, `masscan`, `zmap` and `rustscan` in either fake shell
ignore the target given and report on the attacker's own address, ending with
what this honeypot has actually recorded about them:

```
Host script results:
| clients-observed:
|   address: 203.0.113.44
|   first seen: 2026-07-26T11:04:12
|   sessions logged: 7
|   services probed: ssh, http, ftp
|   credentials offered: 214
|_  threat score: 47
```

Nothing is really scanned. The honeypot has no egress by design, and scanning
back would be a live port scan aimed at a third party — frequently a victim's
compromised box rather than the attacker's own machine — and would expose this
host besides. The port list is fabricated deterministically from their address;
only the observed block is real. `HONEYPOT_SCANBACK=0` turns it off, which you
may want: a careful attacker reads that block and leaves, and the rest of the
session goes with them.

**GeoIP** — country and city on every attacker, and coordinates for the Kibana
map. Needs a free [MaxMind](https://www.maxmind.com/en/geolite2/signup)
GeoLite2 database, which is licensed and cannot ship here:

```bash
# MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env, then
./deploy/update-geoip.sh
echo '0 4 * * 1 root /opt/drosera/deploy/update-geoip.sh' | sudo tee /etc/cron.d/drosera-geoip
```

Without it, geolocation falls back to Cloudflare's country header, which only
exists for proxied web traffic — so SSH, telnet, SMB and RDP show nothing.

**World map** — the attack map draws attack origins over a landmass outline.
Natural Earth 110m, public domain, ~100 KB:

```bash
./deploy/update-worldmap.sh
```

Unlike the GeoIP database this may be redistributed, so once fetched you can
commit `admin-dashboard/static/world.geojson` and nobody else needs to run it.
Without the file the map falls back to a lat/lon graticule — the dots are still
correctly placed, there is just no coastline behind them.

**Elasticsearch + Kibana** — T-Pot-style analytics, off by default because they
want ~2.5 GB. On a small VPS, run them somewhere else instead: copy
`storage/logs/` to a machine with spare memory and start the profile there. The
shipper reads events off the filesystem and never talks to the honeypot, so it
does not care where it runs.

**Automatic TLS** — a certbot container doing DNS-01 through Cloudflare, for
running unproxied. If you are behind Cloudflare's proxy, an Origin Certificate
is 15 years and no renewal machinery, and is the better choice.

**Telegram delivery** — set `ALERT_TELEGRAM_BOT_TOKEN` and
`ALERT_TELEGRAM_CHAT_ID`. Message the bot once first; bots cannot open a
conversation.

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
session handler, so a low `HONEYPOT_TARPIT_THRESHOLD` means you tarpit exactly
the attackers worth watching. Raise it to ~20. Beyond that, most short clips are
genuine: credential-validation bots log in, read the prompt, and leave. A
three-line cast is a complete `ssh host '<cmd>'` session — banner, command,
output.

**A fix appears not to work.** Check you rebuilt rather than restarted (see the
two rules above). The recording's *filename timestamp* is a quick way to tell
old captures from new: it is stamped when the recorder opened, so a cast created
before a change will still show the old behaviour forever.

**You tarpit or ban yourself.** Browsing your own site scores you like anyone
else. Put your address in `HONEYPOT_IGNORE_IPS` (comma-separated) — ignored
addresses are never scored, tarpitted or banned, and stay out of the statistics,
but still record normally so you can test. Already flagged? Clear it:

```bash
MD5=$(printf '%s' "203.0.113.10" | md5sum | cut -d' ' -f1)
docker exec hp-redis-honeypot redis-cli DEL "hp:identity:$MD5" "hp:banned:$MD5"
```

A blank terminal when you connect to your own honeypot is the SSH tarpit
working — it drips the version banner one byte per second, so the client waits
forever for a complete string.

**Ad-hoc log analysis under-counts.** The event log has two producers, PHP and
Python, and until recently they wrote different JSON spacing — `"service":"web"`
versus `"service": "web"`. A grep pattern written against one skipped every line
from the other, silently. New events are uniform; log files written before the
fix still contain both. Match either way, or parse the JSON:

```bash
grep -o '"service": *"[a-z]*"' storage/logs/*.jsonl | tr -d ' ' | sort | uniq -c
```

**Clips render but never arrive.** `no channels configured` on the Sessions page
means no delivery is set up. Only `session-cam` can reach the internet; the
honeypot containers have no egress, so alerting configured for them is inert by
design.

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
