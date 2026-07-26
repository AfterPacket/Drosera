# Drosera Deployment Guide

Complete walkthrough for putting this on a dedicated VPS with a real domain
behind Cloudflare.

Read [`../AUTHORIZATION.md`](../AUTHORIZATION.md) first and fill in the operator
attestation. Confirm your hosting provider permits honeypot operation.

---

## 1. Prerequisites

- Ubuntu 22.04 LTS or 24.04 LTS, freshly installed
- Docker Engine 24+ and Compose v2

**If you want one answer: 4 vCPU / 8 GB RAM / 160 GB NVMe, x86.** That runs
everything including the search stack with headroom. A Hetzner CPX31 or
equivalent is the value pick. Choose x86 over ARM — the Elastic images exist for
arm64, but do not make the architecture a second variable on first deployment.

Running lean is fine too, and much cheaper: 2 vCPU / 4 GB / 40 GB (a Hetzner
CX22 at roughly €4/mo) fits the honeypot, tarpits, camera and dashboard, with
Elasticsearch left behind its `elastic` profile. On a box that size, tighten the
resource ceilings — the defaults are generous and oversubscribe 4 GB:

```bash
docker compose -f docker-compose.yml -f deploy/compose.small.yml up -d
```

You can still have the search stack without paying for it on the VPS: copy
`storage/logs/` down to a machine you already own and run `--profile elastic`
there. The shipper reads events off the filesystem and never connects to the
honeypot, so it does not care how the logs arrived.

Be wary of going cheaper still. Budget hosts and free tiers have the most
automated abuse handling, and a honeypot generates exactly the traffic that
trips it — the risk you take on is the account, not the hardware.

Sizing, by what you actually turn on:

| Configuration | vCPU | RAM | Disk |
|---|---|---|---|
| Honeypot + tarpits + dashboard | 2 | 2 GB | 40 GB |
| \+ session camera (video rendering) | 2 | 3 GB | 40 GB |
| \+ Elasticsearch and Kibana | 2 | 6 GB | 80 GB |

Tarpits are memory-bound rather than CPU-bound — they hold idle sockets, they do
not compute. The search stack is what actually costs you: budget ~2.5 GB for it
alone, and leave it behind its `elastic` profile if the box is small. Rendering
is a brief CPU spike per session, not a sustained load.

The 6 GB row is a floor, not a recommendation. Summing every `mem_limit` in
`docker-compose.yml` gives 7.2 GB. Steady state is nearer 3 GB, but the ceilings
can land together — a clip render during an Elasticsearch merge while tarpits
hold a few hundred sockets — and at 6 GB that combination swaps.

Disk is dominated by captured data. 40 GB is comfortable at
`HONEYPOT_MAX_STORAGE_MB=4096` plus clips; go to 80 GB if you enable
Elasticsearch, which keeps its own copy of every event for
`ELASTIC_RETENTION_DAYS`.
- A domain you control, with its nameservers on Cloudflare
- **A VPS provider that permits honeypots.** Check the AUP before you deploy.
  Most providers are fine with inbound-only deception on your own box, but some
  read "runs services impersonating a business" as prohibited. Hetzner, OVH and
  Vultr have all been used for this; the failure mode is a suspended account
  after an automated abuse report, so it is worth two minutes up front.
- **Nothing else running on this box.** The core premise is that no legitimate
  traffic ever arrives. Do not co-host anything real.

```bash
# Docker, if not already present
curl -fsSL https://get.docker.com | sh
apt-get install -y ufw fail2ban logrotate git
```

Clone to a stable path. The examples assume `/opt/drosera`:

```bash
git clone <your-repo> /opt/drosera
cd /opt/drosera
```

---

## 2. Understand the exposure before you start

Cloudflare's proxy only covers HTTP/HTTPS. It **cannot** proxy SSH, FTP, telnet,
SMTP, MySQL, SMB, or RDP. Those ports are reachable on the VPS's real IP, and
anyone who finds that IP can also reach ports 80/443 directly, bypassing
Cloudflare.

That is acceptable — even useful — for a honeypot: direct scanners are exactly
what you want to catch. Just be clear that Cloudflare here provides TLS
termination, a plausible front, and bot filtering on the web tier. It is not a
containment boundary.

The real containment boundary is the Docker configuration: both networks are
`internal: true`, so no container can make an outbound connection.

---

## 3. Host hardening

Run the bootstrap script. It is idempotent — safe to re-run.

```bash
sudo ADMIN_IP=$(curl -s ifconfig.me) ./deploy/bootstrap.sh
```

`ADMIN_IP` should be the address **you** administer from. If it is dynamic, use
your ISP's CIDR, or omit it and rely on key-only auth.

What it does:

| Step | Detail |
|---|---|
| Storage layout | `storage/{logs,sessions,evidence,upload-tmp}` owned by UID 1000, mode 0750 |
| Dashboard dirs | `admin-dashboard/{config,admin-logs}` mode 0700 |
| ufw | default deny in / allow out; opens 21, 22, 23, 25, 80, 139, 443, 445, 3306, 3389, 30000-30019; opens 2222 only from `ADMIN_IP` |
| fail2ban | installs filter, `ufw-honeypot` action, and the jail pointed at your evidence log |
| logrotate | 90-day JSONL retention, 26-week evidence retention |
| watchdog | cron job every 10 min (see §10) |
| sysctl | raises conntrack limits for tarpit workloads |

The ufw rules it applies, for reference:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp && ufw allow 443/tcp
ufw allow 21/tcp && ufw allow 22/tcp && ufw allow 23/tcp && ufw allow 25/tcp
ufw allow 139/tcp && ufw allow 445/tcp
ufw allow 3306/tcp && ufw allow 3389/tcp
ufw allow 30000:30019/tcp                            # FTP passive range
ufw allow from ADMIN_IP to any port 2222 proto tcp   # real SSH, after cutover
ufw enable
```

---

## 4. Configure

```bash
cp .env.example .env   # bootstrap.sh does this if missing
nano .env
```

At minimum set `DOMAIN`. Every other value has a working default. The
fail-safe settings deserve a look:

| Variable | Default | What it protects against |
|---|---|---|
| `HONEYPOT_MAX_STORAGE_MB` | 4096 | Attack floods filling the disk |
| `TARPIT_MAX_CONCURRENT` | 24 | Tarpits starving PHP-FPM (must stay under `pm.max_children` = 64) |
| `TARPIT_MAX_SECONDS` | 900 | A single request pinning a worker forever |
| `SSH_MAX_CONNECTIONS` | 200 | Thread exhaustion in the SSH honeypot |
| `REDIS_MAXMEMORY` | 512mb | Millions of forged source IPs exhausting RAM |

There are **no secrets in `.env`**. The admin password and TOTP secret live only
in `admin-dashboard/config/admin-config.json`, created in §7.

---

## 5. Point the domain at the VPS

In the Cloudflare dashboard for your zone:

1. **DNS** → add an `A` record: name `@`, value your VPS IP, **Proxy status:
   Proxied** (orange cloud). Add `www` the same way if you want it.
2. **SSL/TLS** → Overview → set encryption mode to **Full (Strict)**.
   Leave it on **Full** until §6 installs the origin certificate.
3. **SSL/TLS** → Edge Certificates → **Always Use HTTPS: On**,
   **Minimum TLS Version: 1.2**.
4. **Speed** → Optimization → **Rocket Loader: Off**. It rewrites your HTML and
   breaks the deliberate WordPress tells.
5. **Security** → Bots → **Bot Fight Mode: On**.
6. **Security** → WAF → set custom rules to **Log** rather than Block. Blocking
   at the edge means the honeypot never sees the attack, which defeats the point.
7. **Caching** → Configuration → **Caching Level: Standard**. Do not enable
   "Cache Everything" — cached tarpit responses would be served by Cloudflare
   instead of dripping from your origin.

DNS propagation is usually under a minute on Cloudflare.

---

## 6. Install the Cloudflare Origin Certificate

This is what makes **Full (Strict)** work. Cloudflare issues it; it is trusted
only by Cloudflare, which is exactly right for an origin.

1. Cloudflare dashboard → **SSL/TLS** → **Origin Server** → **Create Certificate**
2. Keep the defaults (RSA 2048; hostnames `example.com, *.example.com`; 15 years)
3. Copy both PEM blocks onto the VPS:

```bash
sudo nano /opt/drosera/certs/origin.pem    # paste the certificate
sudo nano /opt/drosera/certs/origin.key    # paste the private key
sudo chmod 600 /opt/drosera/certs/origin.key
sudo chmod 644 /opt/drosera/certs/origin.pem
```

4. Switch Cloudflare SSL/TLS mode to **Full (Strict)**.

If these files are absent, the container generates a self-signed certificate so
nginx still starts — but Full (Strict) will fail until the real one is in place.
`certs/` is gitignored; never commit the key.

---

## 7. Create the dashboard admin account

```bash
docker compose build admin-dashboard
docker compose run --rm admin-dashboard python3 setup.py
```

You will be asked for a username, a password (≥16 chars, mixed case, digit,
symbol), and the source IPs allowed to reach the dashboard (default `127.0.0.1`,
which is correct for SSH-tunnel access).

It prints a QR code as terminal art. Scan it with Google Authenticator, Authy,
or 1Password.

> **Store the base32 secret in your password manager immediately.** There are no
> backup codes. Losing it means re-running `setup.py` over SSH.

The file is written mode 0600 to `admin-dashboard/config/admin-config.json` and
is gitignored.

---

## 8. Move real SSH off port 22

The honeypot wants port 22. Your real SSH has to move first.

```bash
sudo ADMIN_IP=$(curl -s ifconfig.me) ./ssh-real/cutover.sh
```

The script uses a deadman switch rather than a self-test, because testing SSH
from the box itself goes over loopback and bypasses ufw entirely — it would
"pass" even while locking you out.

1. It backs up `sshd_config`, makes sshd listen on **both** 2222 and 22, opens
   2222 for your IP, and arms a 90-second rollback.
2. **Leave your session open.** From a *new* terminal:
   ```bash
   ssh -p 2222 -i ~/.ssh/id_ed25519 you@your-vps
   ```
3. In that new session, cancel the rollback:
   ```bash
   sudo /opt/drosera/ssh-real/cutover.sh --confirm
   ```

If step 2 fails, do nothing. SSH restores itself to port 22 after 90 seconds.
To roll back at once: `sudo ./ssh-real/cutover.sh --rollback`.

A timestamped report is written to `/root/ssh-cutover-report.txt`.

Once confirmed, remove the lingering `Port 22` line from `/etc/ssh/sshd_config`
and restart sshd, so the honeypot can bind it.

---

## 9. Start the stack

Validate everything statically before starting anything:

```bash
./deploy/preflight.sh
```

Then bring it up:

```bash
docker compose up -d --build
docker compose ps
```

All **twelve** services should show `running` (fifteen with `--profile
elastic`), and `hp-web`, `hp-redis-honeypot`, `hp-redis-admin` and
`hp-admin-dashboard` should reach `healthy` within a minute.

Then run the functional checks, which cover every port, render a real clip, and
assert the containment boundary in both directions:

```bash
./deploy/smoke-test.sh              # add --elastic if you started that profile
```

Verify the containment boundary — this **must** fail:

```bash
docker compose exec ssh-honey python3 -c \
  "import socket; socket.create_connection(('1.1.1.1',53),timeout=5)"
# expected: OSError / timeout. If it succeeds, the network is not internal.
```

Verify the fake site is up:

```bash
curl -sI https://your-domain.com/ | head -3
curl -s  https://your-domain.com/ | grep generator     # WordPress 6.4.3 tell
```

---

## 10. Fail-safes

| Layer | Mechanism | Where |
|---|---|---|
| Disk | Writes stop above `HONEYPOT_MAX_STORAGE_MB` | `shared/alerting.py`, `web/lib/drosera.php` |
| Disk | Watchdog prunes >90d at 80% full, emergency prune at 92% | `deploy/watchdog.sh` |
| Disk | Container logs capped at 10 MB × 3 per service | `docker-compose.yml` |
| Disk | logrotate on JSONL, evidence, and audit logs | `deploy/logrotate-drosera` |
| Memory | Redis capped with `allkeys-lru` eviction | `docker-compose.yml` |
| Memory | Per-container `mem_limit` and `pids_limit` | `docker-compose.yml` |
| Workers | Global tarpit concurrency cap, below `pm.max_children` | `TARPIT_MAX_CONCURRENT` |
| Workers | Hard deadline on every tarpit | `TARPIT_MAX_SECONDS` |
| Connections | SSH honeypot sheds load past `SSH_MAX_CONNECTIONS` | `ssh-honey/fake_sshd.py` |
| Alerting | Bounded queue drops events rather than growing unbounded | `shared/alerting.py` |
| Liveness | Watchdog restarts dead/unhealthy containers every 10 min | `deploy/watchdog.sh` |
| Liveness | `restart: unless-stopped` on every service | `docker-compose.yml` |
| Escape | No egress, read-only rootfs, all caps dropped, non-root | `docker-compose.yml` |

Container escape gets its own treatment in §17.

Watch the watchdog:

```bash
tail -f /var/log/drosera-watchdog.log
```

---

## 11. Access the dashboard

The dashboard binds `127.0.0.1:8443` on the host. It is not reachable from the
internet and is not proxied by nginx.

```bash
ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@your-vps
```

Then open <http://127.0.0.1:8443/> and log in: password, then TOTP. Both are
required — the session is only created after the TOTP step succeeds.

Pages: **Live feed** (auto-refreshing), **Sessions** (asciinema replay),
**Evidence** (fail2ban log), **Stats** (charts), **Audit**, **Settings**.

---

## 12. Test without banning yourself

Test from a VPN exit node or a second VPS — **never** from your admin IP.

```bash
# From the test host
curl -sI  https://your-domain.com/.env                   # scanner path + tarpit
curl -s   https://your-domain.com/wp-login.php | head    # WordPress replica
ssh       root@your-domain.com                           # any password works
nmap -sV -p 21,22,23,25,3306,3389,445 your-domain.com
```

Confirm it registered:

```bash
docker exec hp-redis-honeypot redis-cli KEYS 'hp:identity:*'
tail -f storage/logs/$(date -u +%F).jsonl
```

Confirm the tarpit engages (this should hang, dripping bytes):

```bash
curl -v --max-time 30 https://your-domain.com/backup.sql
```

Clear a test IP afterwards:

```bash
TEST_IP=203.0.113.99
MD5=$(printf '%s' "$TEST_IP" | md5sum | cut -d' ' -f1)
docker exec hp-redis-honeypot redis-cli DEL "hp:identity:$MD5" "hp:banned:$MD5"
sudo ufw delete deny from $TEST_IP to any 2>/dev/null
sudo fail2ban-client set honeypot unbanip $TEST_IP 2>/dev/null
```

**If you lock yourself out:** you still have port 2222 from your `ADMIN_IP`,
which fail2ban's `ignoreip` and the ufw allow rule protect.

---

## 13. Enabling outbound alerting

Both Docker networks are `internal: true`, so webhook, Telegram, and syslog
alerting are inert by default. JSONL logging and the fail2ban evidence log work
without egress and need no changes.

To enable outbound alerts, understand the trade-off first: you are giving a
container that talks to attackers the ability to make outbound connections.

Create `docker-compose.override.yml` (gitignored):

```yaml
services:
  ssh-honey: { networks: [honeypot-internal, egress] }
  web:       { networks: [honeypot-internal, egress] }
  # add only the services whose alerts you actually need

networks:
  egress:
    driver: bridge
```

Then set `ALERT_WEBHOOK_URL` (or the Telegram/syslog variables) in `.env` and
run `docker compose up -d`.

A safer alternative: leave the honeypot sealed and ship `storage/logs/*.jsonl`
off-box with a host-level agent (Vector, Filebeat, Promtail). The host has
egress; the containers never need it.

### The session camera

`session-cam` is the built-in version of that safer alternative, and it is why
you probably do not need the override above.

It renders finished attacker sessions to video and delivers them over Telegram
and/or email. It is the only container in the appliance with internet access,
and it is on **no other network** — recordings reach it through the `storage`
bind mount, a filesystem handoff rather than a network one:

```
honeypot containers ──write .cast──▶ storage/sessions ──read──▶ session-cam ──▶ internet
     (no egress)                     (shared volume)            (egress only)
```

Because there is no network path between the two sides, a compromised honeypot
gains no route out through the camera, and a compromised camera gains no route
into the honeypot network. That asymmetry is the entire reason it is a separate
container instead of a thread inside `shared/alerting.py`.

Configure it in `.env`:

```bash
CAM_ENABLED=true
CAM_MIN_SCORE=5          # only sessions past this score are delivered
CAM_FORMAT=gif           # gif | mp4 | both

ALERT_TELEGRAM_BOT_TOKEN=123456789:ABCDEF...
ALERT_TELEGRAM_CHAT_ID=123456789

CAM_SMTP_HOST=smtp.example.com
CAM_MAIL_FROM=drosera@example.com
CAM_MAIL_TO=you@example.com
```

With no channel configured it still renders clips, and they are viewable in the
dashboard — delivery is the only part that needs egress.

Check it is working:

```bash
docker logs -f hp-session-cam
```

Per-session delivery status (`SENT`, `SKIPPED`, `FAILED`) is shown on the
dashboard's Sessions page, so a silently broken bot token is visible without
reading logs.

**Note on secrets:** the SMTP credentials are passed only to `session-cam`, not
to the honeypot containers. The Telegram variables are still passed to the
honeypot services as well, because `shared/alerting.py` uses them for text
alerts if you ever grant those containers egress — if you do not intend to,
consider removing them from `x-honeypot-env` so the token never sits in the
containers attackers actually reach.

---

## 14. Interpreting sessions

**Replay a session:** Dashboard → Sessions → Play, or locally:

```bash
asciinema play storage/sessions/203.0.113.42_20240115T031244_ssh.cast
```

**Watch the clip:** Dashboard → Sessions → Clip plays the rendered video inline;
*Download* saves it. Clips live in `storage/clips/` and are pruned after
`CAM_RETENTION_DAYS`. They are a convenience, not evidence — the `.cast` is the
record, and any clip can be re-rendered from it:

```bash
docker exec hp-session-cam python3 cam.py --render \
  /var/honeypot/storage/sessions/203.0.113.42_20240115T031244_ssh.cast
```

**What gets recorded.** SSH, telnet, FTP, SMTP, MySQL and the web shell produce
`.cast` recordings. SMB and RDP do not — they are binary protocols with no
terminal to replay — so they are represented in the event log and alerts only.

### Elasticsearch and Kibana

For T-Pot-style analytics — aggregations, time series, an attack map — the stack
ships events into Elasticsearch and gives you Kibana on top.

```
storage/logs/*.jsonl ──read──▶ elastic-shipper ──▶ elasticsearch ──▶ kibana
                                                   (elastic-internal, no egress)
```

Same containment pattern as the camera: the shipper takes events off the volume
rather than over a network, and **no honeypot container is on
`elastic-internal`**, so nothing an attacker reaches can query, poison, or
delete your search index.

**Before you enable it, check your RAM.** Elasticsearch and Kibana want roughly
2.5 GB between them. On a VPS with less than about 4 GB total, leave this off —
the honeypot itself runs comfortably in well under a gigabyte.

It is behind a Compose profile, so a plain `docker compose up -d` does not start
it and does not require any of its settings. Set both passwords in `.env` first
— the shipper exits immediately without them:

```bash
openssl rand -base64 24   # -> ELASTIC_PASSWORD
openssl rand -base64 24   # -> KIBANA_PASSWORD

docker compose --profile elastic up -d
docker logs -f hp-elastic-shipper
```

Use `--profile elastic` on every later `up`, `down`, and `ps` for this stack, or
Compose will treat those three containers as orphans and offer to remove them.
To turn it off again and reclaim the memory:

```bash
docker compose --profile elastic down       # add -v to drop the index too
```

`elastic-shipper` provisions everything on first run: it sets the
`kibana_system` password, then creates the ILM retention policy, ingest
pipeline, index template, and the Kibana data view. Kibana retries its own
connection, so it recovers on its own once the password lands — a few
authentication errors in the Kibana log during the first minute are expected.

Reach it over the same tunnel as the dashboard:

```bash
ssh -N -L 8443:127.0.0.1:8443 -L 5601:127.0.0.1:5601 -p 2222 you@vps
```

Then <http://127.0.0.1:5601>, username `elastic`, password `ELASTIC_PASSWORD`.
The dashboard's sidebar links straight to it.

**The attack map needs a GeoIP database.** `elastic-internal` has no egress, so
Elasticsearch's GeoIP auto-downloader is disabled and nothing is fetched at
runtime. Sign up free at [MaxMind](https://www.maxmind.com/en/geolite2/signup),
download GeoLite2-City, and drop `GeoLite2-City.mmdb` into `elastic/geoip/`.
Without it the shipper falls back to Cloudflare's `cf_ipcountry` header, which
gives country-level geo for web traffic only.

Retention is `ELASTIC_RETENTION_DAYS` (90 by default) via ILM. That governs the
search index only — `storage/logs/*.jsonl` remains the authoritative record and
is rotated separately by logrotate.

**If you re-index from scratch:** delete the checkpoint and restart the shipper.
Document IDs are derived from file and byte offset, so replaying is idempotent —
you get updates, not duplicates.

```bash
docker compose stop elastic-shipper
rm storage/.elastic-shipper.json
docker compose start elastic-shipper
```

### What this is not

Compared to T-Pot, this stack has the ELK analytics, the honeypot spread, and
the tarpits, but deliberately not: Suricata/p0f (both need host-level packet
capture, which conflicts with the no-privileges container model), Spiderfoot,
CyberChef, or ewsposter community submission. Nothing here reports to a third
party — see `AUTHORIZATION.md` §7 on why sharing captured data is a deliberate
decision rather than a default.

**Read a score.** Points accumulate per IP across every service. Tarpit at 5,
ban at 35 by default. The breakdown table on an IP's detail page shows which
behaviours contributed. A score of 35 reached through `CONNECTION_ANY` alone is
background scanning; 35 reached via `SQLI_OOB` and `REVERSE_SHELL` is a targeted
operator worth reading in full.

**Evidence packages.** Dashboard → an IP → *Export evidence (ZIP)*. Contains the
event log, identity record, session recordings, an HTML summary report, and a
suggested fail2ban line. Suitable for a provider abuse desk or law enforcement.

Before sharing: read §7 of `AUTHORIZATION.md`. Share indicators and behaviour;
do **not** share captured third-party credentials, and never test them anywhere.

---

## 15. Routine maintenance

```bash
# Cloudflare IP ranges change occasionally
curl -s https://www.cloudflare.com/ips-v4
# reconcile against nginx/honeypot.conf and web/lib/drosera.php

# Update images and rebuild
docker compose pull && docker compose up -d --build

# Check disk
df -h /opt/drosera && du -sh storage/*

# Verify fail2ban is acting on bans
sudo fail2ban-client status honeypot
```

**Monitor the monitor.** The honeypot is only useful while it is up, and nothing
will page you when it dies. Point an external uptime service (UptimeRobot,
Healthchecks.io, Better Stack) at `https://your-domain.com/` on a 5-minute
check. It looks like ordinary traffic to the fake site, and it is the only thing
that will tell you the box fell over.

---

## 16. Troubleshooting

| Symptom | Check |
|---|---|
| nginx will not start | `docker compose logs web` — config errors are fatal and explicit |
| 502 on every request | php-fpm died: `docker compose logs web \| grep fpm` |
| No data in the dashboard | `docker exec hp-redis-honeypot redis-cli KEYS 'hp:identity:*'` |
| `setup.py` says "needs a terminal" | Use `docker compose run --rm`, not `exec` |
| Dashboard login loops | Cookie rejected — set `ADMIN_COOKIE_SECURE=false` for tunnel access |
| TOTP rejected | Clock drift: `timedatectl set-ntp true` on the VPS |
| Bans not enforced | `fail2ban-client status honeypot`; confirm `logpath` matches your checkout |
| Port 22 in use | The cutover's `Port 22` line is still in `sshd_config` |
| Tarpit returns 404 instantly | `TARPIT_MAX_CONCURRENT` reached — by design, check the stats page |
| Containers reach the internet | A network lost `internal: true`; check for an override file |

---

## 17. Container escape hardening

### The threat model

A honeypot deliberately invites attackers to interact with services. The
containers hold no real credentials and execute nothing, so the realistic risk
is not "an attacker uses the fake shell" — that shell is a lookup table. The
risk is a **memory-corruption or logic bug in a real component** (paramiko,
PHP-FPM, nginx, the Python runtime) that yields actual code execution, followed
by a **container escape** to the host.

The defence is layered so that code execution inside a container is a dead end.

### Controls in place

| Layer | Control | Effect |
|---|---|---|
| Identity | `USER 1000` in every Dockerfile | No process runs as container-root |
| Privilege | `no-new-privileges:true` | `setuid`/`setgid` cannot raise privilege |
| Privilege | setuid bits stripped at build (`chmod a-s`) | No local escalation binaries exist at all |
| Capability | `cap_drop: [ALL]` | No `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`, `CAP_NET_RAW` |
| Binding | Unprivileged ports + host mapping | `CAP_NET_BIND_SERVICE` never needed |
| Filesystem | `read_only: true` rootfs | Cannot overwrite binaries or drop a payload on disk |
| Filesystem | tmpfs mounted `noexec,nosuid,nodev` | The only writable path cannot execute anything |
| Filesystem | `storage/` bind-mounted `noexec,nosuid,nodev` | Captured attacker bytes can never be executed |
| Kernel | Default seccomp profile (not disabled) | ~44 dangerous syscalls blocked, incl. `mount`, `ptrace`, `bpf`, `keyctl` |
| Kernel | Default AppArmor (`docker-default`) | Blocks writes to `/proc/sys`, `/sys`, raw devices |
| Namespace | No `pid:`/`network_mode:`/`ipc: host` | No visibility into host processes or network stack |
| Socket | Docker socket never mounted | The single most common escape route is absent |
| Devices | No `devices:` entries, no `privileged` | No raw block-device access to the host filesystem |
| Resources | `pids_limit`, `mem_limit`, `cpus`, `ulimits` | Fork bombs and resource exhaustion are contained |
| Network | Both networks `internal: true` | Even with code execution, no outbound channel |
| Daemon | `no-new-privileges`, `userland-proxy: false`, `icc: false` | Applied by `bootstrap.sh` to `/etc/docker/daemon.json` |

Note the interaction that matters most: **read-only rootfs + noexec tmpfs +
no egress**. An attacker with code execution in a honeypot container has nowhere
to write a payload, nowhere to execute one from, and no way to fetch one.

### Verify it

Run these after `docker compose up -d`. Every one should fail.

```bash
# No egress
docker compose exec ssh-honey python3 -c \
  "import socket; socket.create_connection(('1.1.1.1',53),timeout=5)"

# Root filesystem is read-only
docker compose exec web sh -c 'touch /root-test' ; echo "exit=$?"

# /tmp is writable but not executable
docker compose exec web sh -c \
  'printf "#!/bin/sh\necho pwned\n" > /tmp/x && chmod +x /tmp/x && /tmp/x'

# Not running as root
docker compose exec web id          # expect uid=1000
docker compose exec ssh-honey id    # expect uid=1000

# No capabilities
docker compose exec web sh -c 'grep CapEff /proc/self/status'   # expect 0000000000000000

# No docker socket
docker compose exec web sh -c 'ls -l /var/run/docker.sock'      # expect not found

# Captured data cannot be executed
docker compose exec web sh -c \
  'printf "#!/bin/sh\necho x\n" > /var/honeypot/storage/x && chmod +x /var/honeypot/storage/x && /var/honeypot/storage/x'
```

Confirm seccomp and AppArmor are actually applied (not `unconfined`):

```bash
docker inspect hp-web --format '{{ .HostConfig.SecurityOpt }}'
docker inspect hp-web --format '{{ .AppArmorProfile }}'
docker compose exec web grep Seccomp /proc/self/status   # expect Seccomp: 2
```

### Optional: user namespace remapping

The strongest remaining mitigation. With `userns-remap`, UID 0 inside a
container maps to an unprivileged host UID, so even a full container-root
compromise lands as nobody on the host.

It is **not** enabled by `bootstrap.sh` because it remaps bind-mount ownership,
which breaks `storage/` and `admin-dashboard/config/` until they are re-chowned
into the mapped range.

To enable it:

```bash
# 1. Add to /etc/docker/daemon.json
#      "userns-remap": "default"
sudo systemctl restart docker

# 2. Find the mapped base UID
grep dockremap /etc/subuid          # e.g. dockremap:231072:65536

# 3. Re-chown the writable bind mounts into the mapped range.
#    Container UID 1000 becomes host UID <base + 1000>.
BASE=231072
sudo chown -R $((BASE+1000)):$((BASE+1000)) \
  /opt/drosera/storage /opt/drosera/admin-dashboard/config \
  /opt/drosera/admin-dashboard/admin-logs

# 4. Rebuild and restart
cd /opt/drosera && docker compose up -d --force-recreate
```

Named volumes (`redis-honeypot-data`, `redis-admin-data`, `ssh-host-key`) are
handled automatically. Verify with `docker compose exec web id` and check the
host-side UID with `ps -eo uid,cmd | grep nginx`.

### Host maintenance

Container isolation ultimately rests on the kernel. Keep it patched:

```bash
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Enable automatic reboots for kernel updates in
`/etc/apt/apt.conf.d/50unattended-upgrades` (`Unattended-Upgrade::Automatic-Reboot "true";`
with a reboot time). A honeypot going down for two minutes at 04:00 costs
nothing; running a kernel with a known `runc` or `overlayfs` escape costs a lot.

### If you suspect a real compromise

The honeypot is designed to be disposable. Do not investigate in place.

1. `docker compose down` — stop everything.
2. Snapshot the VPS if your provider supports it, for later analysis.
3. Copy `storage/` off-box for evidence.
4. **Rebuild the VPS from scratch.** Do not attempt to clean it.
5. Rotate anything that ever touched the box: the Cloudflare origin key
   (`certs/origin.key`), your SSH keys, the dashboard credentials.
6. Treat the previous public IP as burned; take a new one if you can.
