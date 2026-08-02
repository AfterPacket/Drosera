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
| `loot.py` | Content-addressed quarantine for dropped payloads. Files land 0400 under `storage/loot/`, named by SHA-256 so an attacker never influences a path; per-file and total size caps; deduplicated by hash with a bounded sighting list. Nothing here opens or interprets a sample. `clear_scan()` drops a recorded verdict so the sample is offered to VirusTotal again — called by `intel`, never by a honeypot or the dashboard |
| `persona.py` | Reads `/persona/persona.json`: the machine this deployment pretends to be. Banners, hostname/kernel/user pools, shell history, honeytoken credentials, fake-file sizes. Falls back to published defaults so a fresh clone runs |
| `rickroll.py` | Loads `rickroll.txt` for the SSH and telnet ban paths, which drip it through `tarpit.drip`/`drip_sync` rather than sending it at once. `HONEYPOT_RICKROLL=0` restores the silent drop |
| `rickroll.txt` | The art itself, read by all three tiers. LF in the repository; converted to CRLF for the terminal services because a socket has no line discipline. Bind-mounted into the web container at `/rickroll.txt` — `web/` is the only thing that container gets, so this one file is mounted explicitly, at the root rather than under the read-only `/var/www/html` mount. `deploy/preflight.sh` asserts it |
| `llm.py` | Optional generated answers for commands `fakeshell.py` does not implement. Opens no socket: the honeypot containers have no egress, so a request is written to `storage/llm/requests/` and `llm-broker` answers it. Every failure path returns `None` and the shell prints `command not found` as before, including a fast-fail when no broker is publishing |
| `crash.py` | Procedurally generated malformed responses for the tier between the tarpit and the ban. Sent before the handshake, so an address in crash mode stops producing credentials, transcripts and payloads — weigh that before raising `HONEYPOT_CRASH_THRESHOLD`. `HONEYPOT_CRASH=0` disables it and releases anyone already flagged |
| `nmap.py` | Detection only: whether a banner or request path names nmap. Opens no socket and runs no process, deliberately — see the module docstring and `AUTHORIZATION.md` §7. Answering a probe is the caller's job, in the protocol it arrived on |
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
| `render.py` | asciicast v2 → animated GIF via pyte + Pillow, with a security-camera HUD, then MP4 via ffmpeg. Renders every frame by default; the frame budget applies only when the GIF is the delivered artefact. No binary is fetched at build time — ffmpeg comes from Debian's archive |
| `cam.py` | Watches for finished recordings, gates on score/duration, renders, and delivers over Telegram, SMTP email, and webhook. Idempotent via `.cam.json` markers; prunes clips on age and total size |
| `Dockerfile` | python:3.11-slim + DejaVu mono + CA certificates + ffmpeg, non-root, setuid stripped |

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
| `app.py` | Flask app. Two-stage auth (session created only after TOTP), CSRF, login rate limiting, IP allowlist, all routes. `/api/stats?day=` recomputes any retained day from its own log file; `/api/stats/trend` returns per-day totals for the day picker's history chart |
| `app.py` (loot) | `/loot` lists the quarantine with MD5 and SHA-1 derived on read and cached, since `loot.capture` stores only the SHA-256. `/api/loot/download` returns an AES zip — live samples, so encrypted against the operator's own AV rather than for secrecy. `/api/loot/rescan` writes a marker to `storage/requests/`, the only path on the volume this container mounts read-write, because it cannot clear a verdict itself and must not be able to |
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
| `bootstrap.sh` | Host preparation: storage, ufw, fail2ban, logrotate, watchdog, sysctl, egress rules |
| `generate-persona.sh` | Writes `persona/persona.json`: randomised banners, hostnames, kernels, company, credentials and file sizes. Run once before going live; the result is gitignored and worth backing up |
| `watchdog.sh` | Cron fail-safe: enforces the 90-day event-log retention, prunes storage under disk pressure, restarts dead or unhealthy containers |
| `logrotate-drosera` | Retention policy for the evidence and audit logs. Deliberately does **not** cover `storage/logs/*.jsonl`, which is already one file per day |
| `clean-stale-nft.sh` | Removes `raw` PREROUTING rules naming a bridge that no longer exists. Docker leaks these when a network is destroyed during a daemon restart, and they then drop every packet to the addresses they name — invisibly, since that chain runs before conntrack and before FORWARD |
| `update-geoip.sh` | Fetches the MaxMind GeoLite2 database with the operator's credentials. Run from cron; MaxMind refreshes weekly |
| `update-worldmap.sh` | Fetches the Natural Earth land outline for the attack map. Public domain, so the result can be committed |
| `preflight.sh` | Static validation before deploying: Python/PHP/shell syntax, `docker compose config` on both profiles, `.env` sanity, git-safety of secret paths, host RAM and `vm.max_map_count` |
| `smoke-test.sh` | Post-deploy functional checks: container health, every honeypot port, SSH banner, dashboard `/healthz`, a real GIF rendered from a synthetic recording, Elasticsearch doc count and ILM state, and an explicit assertion that honeypot containers cannot reach the internet while session-cam can |

## `intel/`

| File | Purpose |
|---|---|
| `vt.py` | VirusTotal hash lookups for quarantined payloads. Runs on `cam-egress` with no listening ports. Reads the JSON sidecars and the hash in the filename, never a captured sample, so the one container with internet access never opens attacker input. Sends a hash and not the file — see the module docstring for why that is a decision rather than a default |
| `Dockerfile` | stdlib only. Depends on `shared/__init__.py` importing lazily; an eager import there lands here |

## `llm-broker/`

Under the `llm` profile. Absent from a default deployment.

| File | Purpose |
|---|---|
| `broker.py` | The only container permitted to talk to a language model. Runs on `llm-egress` with no listening ports; work arrives over the storage volume, as it does for `session-cam`. Supports Ollama, Anthropic, OpenAI and xAI. Enforces hourly and per-address call caps, and validates every response before it can reach an attacker — anything reading like an assistant is discarded in favour of the fallback. Publishes counters to `storage/llm/status.json` for the Settings page |
| `test_broker.py` | Pins both edges of `sanitise()`: plausible terminal output survives, anything that broke character does not. Also covers the budget and prompt construction |
| `Dockerfile` | stdlib only, deliberately. This container has both internet access and attacker-derived input in memory, so it carries no third-party Python to audit |

## `persona/`

| File | Purpose |
|---|---|
| `README.md` | Why the persona is generated rather than committed, and why to back it up |
| `persona.json` | This deployment's identity. Gitignored. Created by `deploy/generate-persona.sh` |

## `ssh-real/`

| File | Purpose |
|---|---|
| `cutover.sh` | Moves real SSH to 2222 using a deadman switch with `--confirm` / `--rollback` |

## Created at runtime (gitignored)

| Path | Contents |
|---|---|
| `storage/logs/YYYY-MM-DD.jsonl` | Every event. One file per UTC day, which *is* the rotation — never point logrotate at this tree |
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
