# File Manifest

What each file is and why it exists. Verify against this rather than assuming —
an earlier revision of this document claimed the project was complete when most
services were stubs.

## Root

| File | Purpose |
|---|---|
| `docker-compose.yml` | Service orchestration and the containment model (internal networks, read-only rootfs, dropped capabilities, resource caps) |
| `.env.example` | Configuration template. Copy to `.env`. Contains no secrets |
| `.gitignore` | Excludes secrets, TLS keys, captured attacker data, and the author's working notes |
| `AUTHORIZATION.md` | Legal/ethical basis, operator attestation, data-protection posture |
| `README.md` | Project overview |
| `QUICKSTART.md` | Condensed deployment path |
| `MANIFEST.md` | This file |

## `shared/` — Python modules, bind-mounted read-only into every service

| File | Purpose |
|---|---|
| `identity.py` | Per-IP fake machine identity, scoring, tarpit/ban state. Redis is the source of truth; degrades to an in-process cache if Redis is unreachable |
| `scoring.py` | Event point table and the ban/tarpit thresholds |
| `alerting.py` | JSONL, fail2ban, webhook, Telegram, RFC 5424 syslog, and the asciinema v2 recorder. Bounded queue on a worker thread. Writes the `.meta.json` sidecar that tells `session-cam` a recording is finished |
| `tarpit.py` | Slow-drain helpers for the asyncio services: byte-at-a-time PDU dripping and randomised per-response stalls, both deadline-bounded |
| `fakeshell.py` | Simulated bash. Table-driven; executes nothing |
| `persona.py` | Reads `/persona/persona.json`: the machine this deployment pretends to be. Banners, hostname/kernel/user pools, shell history, honeytoken credentials, fake-file sizes. Falls back to published defaults so a fresh clone runs |
| `__init__.py` | Re-exports the public surface |

## `web/` — public site, webshell, tarpit

| File | Purpose |
|---|---|
| `lib/drosera.php` | Shared runtime: Redis client (phpredis with a raw RESP/fsockopen fallback), IP resolution, scoring, tarpit engine, logging. Outside the document root |
| `lib/persona.php` | PHP half of the persona reader. Same `/persona/persona.json` the Python honeypots read, so the website and the fake shell agree about what machine this is |
| `index.php` | Webshell UI (cmd/php/mysql/files/info/network) and the crawler trap. Outside the document root; reachable only via nginx's explicit mappings |
| `public_site/index.html` | Template for the fake business site, with honeytoken comments. Never served directly — `/index.html` goes to the trap |
| `public_site/home.php` | Renders `index.html` with this deployment's persona. What `/` actually serves |
| `public_site/robots.txt` | Disallow list that doubles as scanner bait |
| `public_site/sitemap.php` | Sitemap generated with the real serving host; entries lead into the crawler trap. Served at `/sitemap.xml` |
| `public_site/wp-login.php` | WordPress 6.4.x login replica; records credentials |
| `public_site/xmlrpc.php` | XML-RPC endpoint; detects `system.multicall` brute force |
| `public_site/contact-form-handler.php` | Contact form; scores injection payloads. Never sends mail |
| `public_site/catch_scanner_paths.php` | Catch-all. Serves fake `.env`, `.git/config`, `wp-config.php`, adminer/phpMyAdmin pages, and the endless SQL-dump tarpit |
| `nginx.conf` | Main nginx config. `log_format` lives here — it is illegal in a server block |
| `php-fpm.conf` | Pool config. `pm.max_children` is sized above `TARPIT_MAX_CONCURRENT` |
| `entrypoint.sh` | Resolves TLS material, starts php-fpm and nginx, exits if either dies |
| `Dockerfile` | Ubuntu 22.04 + nginx-full + PHP 8.1-FPM, running as UID 1000 |

## Protocol honeypots

Each directory holds a service and its Dockerfile. All bind unprivileged ports
inside the container; the host maps the real port.

| Service | Container port → host | Notes |
|---|---|---|
| `ssh-honey/fake_sshd.py` | 2222 → 22 | Threaded, endlessh-style tarpit, fake shell, SFTP sink, session recording |
| `ftp-honey/fake_ftpd.py` | 2121 → 21 | Full command set, PASV and PORT, uploads discarded |
| `telnet-honey/fake_telnetd.py` | 2323 → 23 | IAC negotiation, non-terminal client fingerprinting |
| `smtp-honey/fake_smtpd.py` | 2525 → 25 | Advertises open relay, delivers nothing |
| `mysql-honey/fake_mysqld.py` | 33306 → 3306 | Protocol v10 wire format, bounded time-based-blind sleep |
| `smb-honey/fake_smbd.py` | 4445 → 445, 4139 → 139 | SMB2 negotiate/session/tree, NTLMv2 capture in hashcat format, per-response tarpit stalls |
| `rdp-honey/fake_rdpd.py` | 33389 → 3389 | X.224, parses the mstshash cookie, drips the Connection Confirm when tarpitted |

## `session-cam/` — session camera

Renders finished attacker sessions to video and delivers them. The only
container with internet access, and deliberately on no other network:
recordings reach it through the `storage` volume, so egress here is not egress
for the honeypot.

| File | Purpose |
|---|---|
| `render.py` | asciicast v2 → animated GIF via pyte + Pillow, with a security-camera HUD. Optional MP4 when ffmpeg is present. Pure Python: no binary fetched at build time |
| `cam.py` | Watches for finished recordings, gates on score/duration, renders, and delivers over Telegram, SMTP email, and webhook. Idempotent via `.cam.json` markers; prunes clips on age and total size |
| `Dockerfile` | python:3.11-slim + DejaVu mono + CA certificates, non-root, setuid stripped |

## `elastic/` — search and analytics

Elasticsearch + Kibana for T-Pot-style stats. On `elastic-internal`, which no
honeypot container is a member of.

| File | Purpose |
|---|---|
| `shipper.py` | Tails `storage/logs/*.jsonl` into Elasticsearch `_bulk`, and provisions the ILM policy, ingest pipeline, index template, `kibana_system` password and Kibana data view on startup. Checkpoints byte offsets; document IDs are derived from (file, offset) so a replay updates rather than duplicates |
| `geoip/` | Drop `GeoLite2-City.mmdb` here for attack-map coordinates. Not auto-downloaded — the network has no egress |
| `Dockerfile` | python:3.11-slim, non-root, setuid stripped |

## `admin-dashboard/`

| File | Purpose |
|---|---|
| `app.py` | Flask app. Two-stage auth (session created only after TOTP), CSRF, login rate limiting, IP allowlist, all routes |
| `setup.py` | First-run: bcrypt hash, TOTP secret, terminal QR code. Writes config mode 0600 |
| `templates/` | Jinja templates, autoescaped |
| `static/` | CSS and JS. Scripts are external files because the CSP forbids inline |
| `requirements.txt` | Pinned dependencies |
| `Dockerfile` | Runs under gunicorn as UID 1000 |
| `admin-config.example.json` | Template only — never edit by hand |

## `nginx/`

| File | Purpose |
|---|---|
| `honeypot.conf` | Site config: Cloudflare real-IP, TLS, routing, trap fallbacks |

## `fail2ban/`

| File | Purpose |
|---|---|
| `honeypot-filter.conf` | Matches `HONEYPOT_BAN` lines |
| `honeypot-jail.conf` | `maxretry = 1` — the honeypot already made the decision |
| `action.d/ufw-honeypot.conf` | Single blanket ufw deny per banned address |

## `deploy/`

| File | Purpose |
|---|---|
| `README.md` | Full deployment guide |
| `bootstrap.sh` | Host preparation: storage, ufw, fail2ban, logrotate, watchdog, sysctl |
| `generate-persona.sh` | Writes `persona/persona.json`: randomised banners, hostnames, kernels, company, credentials and file sizes. Run once before going live; the result is gitignored and worth backing up |
| `watchdog.sh` | Cron fail-safe: prunes storage, restarts dead or unhealthy containers |
| `logrotate-drosera` | Retention policy (90 days for event logs) |
| `update-geoip.sh` | Fetches the MaxMind GeoLite2 database with the operator's credentials. Run from cron; MaxMind refreshes weekly |
| `update-worldmap.sh` | Fetches the Natural Earth land outline for the attack map. Public domain, so the result can be committed |
| `preflight.sh` | Static validation before deploying: Python/PHP/shell syntax, `docker compose config` on both profiles, `.env` sanity, git-safety of secret paths, host RAM and `vm.max_map_count` |
| `smoke-test.sh` | Post-deploy functional checks: container health, every honeypot port, SSH banner, dashboard `/healthz`, a real GIF rendered from a synthetic recording, Elasticsearch doc count and ILM state, and an explicit assertion that honeypot containers cannot reach the internet while session-cam can |

## `ssh-real/`

| File | Purpose |
|---|---|
| `cutover.sh` | Moves real SSH to 2222 using a deadman switch with `--confirm` / `--rollback` |

## Created at runtime (gitignored)

| Path | Contents |
|---|---|
| `storage/logs/YYYY-MM-DD.jsonl` | Every event |
| `storage/sessions/*.cast` | asciinema recordings |
| `storage/evidence/fail2ban.log` | Ban lines fail2ban acts on |
| `storage/upload-tmp/` | Upload staging; files are unlinked immediately after hashing |
| `admin-dashboard/config/admin-config.json` | Admin credentials (mode 0600) |
| `admin-dashboard/admin-logs/audit.jsonl` | Operator action audit trail |
| `certs/origin.{pem,key}` | Cloudflare Origin Certificate |

---

## Pre-deployment checklist

- [ ] `AUTHORIZATION.md` attestation completed
- [ ] Hosting provider AUP checked for honeypot operation
- [ ] `.env` created, `DOMAIN` set
- [ ] `sudo ADMIN_IP=... ./deploy/bootstrap.sh` run
- [ ] Cloudflare DNS proxied, SSL mode Full (Strict), Rocket Loader off
- [ ] `certs/origin.pem` and `certs/origin.key` installed, key mode 0600
- [ ] `setup.py` run, TOTP secret stored in a password manager
- [ ] `ssh-real/cutover.sh` run and `--confirm`ed from a new session
- [ ] `docker compose up -d --build`, all services healthy
- [ ] Egress check fails as expected (see deploy/README.md §9)
- [ ] Tested from a VPN or second VPS, not from your admin IP
- [ ] External uptime check configured
