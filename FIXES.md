# Notable fixes

Bugs whose cause was not where the symptom pointed. Kept because the reasoning
is worth more than the diff — several of these were expensive to find, and the
next one will look just as innocent.

---

## "Release tarpit" lasted exactly one packet

**Symptom.** An operator releases an address from the tarpit to watch it work,
and it is back in the tarpit immediately:

```
20:54:27  ssh  TARPIT_ENGAGED  31.0  ssh tarpit
20:54:27  ssh  CONNECTION_ANY  31.0  Initial contact
```

Engaged in the same second as the connection that triggered it.

**Cause.** The release cleared `tarpit_active` and nothing else. The score is
deliberately left alone -- it is the record of what they did -- but that is
exactly why clearing the flag on its own achieves nothing:

```python
should_tarpit = scoring.should_tarpit(new_score)   # 31 >= 20
if should_tarpit and not was_tarpitted:
    fields["tarpit_active"] = True
```

Every scored event re-derives the flag from the score. The attacker's next
connection scores `CONNECTION_ANY`, the score is still over the threshold, and
the tarpit re-engages before the operator has seen anything.

**Why it hid.** The button worked. The audit line was written, the flag really
was cleared, and the API returned success. The window between the release and
the next inbound packet is where it was true, and on a host being scanned that
is milliseconds. `release_tarpit()` even documented the mechanism in its own
docstring -- "clearing it would just let them climb back to the threshold and
re-engage" -- and then did not act on it.

**Fix.** A release is an exemption with a deadline rather than a flag flip.
`tarpit_exempt_until` is honoured by `score_event`, `activate_tarpit` and
`is_tarpitted`, and by the web tier, which keeps its own copy of all three --
otherwise a release would hold on SSH and be undone by the first HTTP request.
It expires (`HONEYPOT_TARPIT_RELEASE_SECONDS`, one hour) because a permanent
release made by accident is invisible afterwards: the address simply never gets
tarpitted again and nothing says why.

**Avoid it.** When a control derives state from a value on every event, setting
the state is not the same as changing the outcome. The question to ask of any
manual override is what recomputes it, and how soon.

**Unban had it too, and worse.** `unban()` cleared the flag and left the score,
so the next scored event re-banned on the same reasoning -- but a ban is not
just a flag. It writes a line to `storage/evidence/fail2ban.log`, and
fail2ban's action is `ufw insert 1 deny from <ip>`. An unban undone a second
later therefore *added* a host firewall rule rather than removing one, and the
operator saw the address banned again with no explanation. Same exemption,
same expiry.

Worth knowing separately: unbanning in the dashboard has never removed an
existing ufw rule and still does not. Those belong to fail2ban, which holds
them for its own `bantime` (7 days here). Drop one by hand:

```
sudo fail2ban-client set honeypot unbanip <ip>
```

---

## One probe was enough to identify the honeypot

**Symptom.** A session that ends 2.8 seconds after a successful login, having
run nothing:

```
20:21:35  ssh  CREDENTIAL_ATTEMPT  charles:charles
20:21:35  ssh  PERSISTENCE_ATTEMPT cd ~; chattr -ia .ssh
20:21:39  ssh  CREDENTIAL_ATTEMPT  345gs5662d34:345gs5662d34
20:21:39  ssh  SESSION_END         Session closed after 2.8s
```

**Cause.** `check_auth_password()` ended:

```python
if identity.is_banned(self.ip):
    return paramiko.AUTH_FAILED
return paramiko.AUTH_SUCCESSFUL
```

Every credential succeeded. The second one there is not a guess — no machine
has that account. It is an accept-all probe: offer something plausible, then
offer something impossible, and if both work the server is not a server. We
accepted it, and they left.

**Why it is the expensive kind of bug.** Nothing failed. The credential was
captured, the event was scored, the recording was written — the honeypot did
every job it thought it had. What it lost was everything downstream: the
loader, the payload, the second stage. The `chattr -ia .ssh` in the line above
shows this was a worm with a persistence chain to run, and it ran none of it.

**Fix.** `shared/credentials.py` decides. Common and guessable credentials are
accepted, because those are what a neglected box with a weak password actually
falls to; machine-generated strings are refused, because no administrator ever
set one and that is exactly why a prober picks one. Telnet gets the same rule,
and now closes the connection after three refusals rather than dropping into
the shell anyway. `HONEYPOT_ACCEPT_ANY_PASSWORD=1` restores the old behaviour.

**Avoid it.** "Accept everything" is not neutral, it is a signature. Anywhere
the honeypot is more permissive than the machine it imitates, that difference
is measurable from the outside in a single request.

---

## SMB1 scanners were answered in a protocol they do not speak

**Symptom.** One connection, five events, gone in a second — then the identical
pattern again:

```
20:16:43  smb  CONNECTION_ANY  Initial contact
20:16:43  smb  SMB_ENUM        SMB1 negotiate
20:16:43  smb  SMB_ENUM        SMB1 negotiate
20:16:43  smb  SMB_ENUM        SMB1 negotiate
20:16:43  smb  SMB_ENUM        SMB1 negotiate
20:16:44  smb  SESSION_END     Session closed after 1.0s
```

**Cause.** Every SMB1 packet — whatever it asked, whatever dialects it offered
— was answered with an **SMB2** NEGOTIATE response:

```python
if payload.startswith(SMB1_MAGIC):
    writer.write(wrap_nbt(negotiate_response(0)))
    continue
```

Steering an SMB1 client to SMB2 is a real mechanism, but only when the client
offered `SMB 2.???` or `SMB 2.002` in its dialect list. A client that offered
neither cannot parse the reply. It retried, four times, and left.

That is the MS17-010 scanner family, which speaks SMB1 and nothing else, and
which is a large fraction of all SMB traffic reaching an exposed host.

**Why the retries were the clue.** Four identical events in the same second is
not a client working through a protocol; it is a client that discarded an
answer and asked again. Nothing errored, and the branch even scored each one,
so the log looked like enumeration rather than a client being talked past.

**Fix.** The dialect list is parsed and logged, and the SMB2 reply now only
goes to clients that asked for SMB2 by name. SMB1-only clients get an SMB1
NEGOTIATE response selecting `NT LM 0.12`, followed by SESSION_SETUP_ANDX —
which captures LM/NTLM responses against the same fixed challenge as the SMB2
path, so they are equally crackable — TREE_CONNECT_ANDX, ECHO, and a parseable
`STATUS_NOT_IMPLEMENTED` for everything else. A client offering dialects we do
not want answers `0xFFFF`, which is a real answer rather than silence.

**Avoid it.** Protocol negotiation is a question, not a formality. Answering
every version of it with the version you prefer is indistinguishable, from the
far end, from being broken.

---

## `echo` printed its own flags, so no bot ever got past the handshake

**Symptom.** A telnet attacker connects, sends one command, and leaves after one
second. The command:

```
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

**Cause.** That decodes to `auth_ok`. It is the handshake a Mirai-family loader
performs immediately after login: send a hex-escaped string, read it back, and
only continue if the shell answered correctly. The implementation was:

```python
def _cmd_echo(self, args, _line):
    return " ".join(args)
```

So the bot got `-e \x61\x75\x74\x68...` — its own flag, and its own escapes
untouched. It concluded this was not a shell and hung up.

A second break sat right behind it: `/bin/busybox MIRAI` is a presence check,
where the loader runs its own tag as an applet and looks for the exact string
`applet not found` before starting the infection chain. Unknown commands
returned bash's `command not found`, which fails that check too.

**What it cost.** Everything after the handshake. The busybox probe, the
`wget`/`tftp` line naming the second stage, the payload itself — the loader URL
extractor and the quarantine fetcher are both downstream of these two
exchanges, so neither had ever seen a Mirai infection attempt through to the
part worth capturing.

**Why it hid.** The session looked like a scanner that touched the port and
moved on, which is most traffic. Nothing errored: `echo` returned a string, the
command was logged, the score went up, the recording was written. The only
evidence was that the sessions were always exactly one command long.

**Fix.** `echo` handles `-e`, `-E`, `-n` and combined forms, and expands
`\xHH`, `\0NNN`, `\n`, `\t`, `\c` and the rest. Unknown escapes pass through
untouched, as bash does, so a payload is recorded verbatim. An unrecognised
applet invoked through busybox answers `applet not found`, while a genuinely
missing command still answers `command not found`.

**Avoid it.** `" ".join(args)` is a reasonable sketch of `echo` and a wrong
implementation of it. In a honeypot the fidelity of the boring builtins is the
product: the interesting behaviour only happens if the dull part convinces.

---

## The honeypot was working its way towards banning its own host

**Symptom.** An attacker profile for `172.25.0.1` — the Docker bridge gateway.
Score 27 of 35, all six services touched, 41 sessions, climbing steadily.

**Cause.** That address is the host reaching into the containers: health checks,
`deploy/smoke-test.sh`, and any `curl` run on the box. Nothing distinguished it
from an attacker. `IGNORE_IPS` existed for exactly this, but it was an opt-in
env var, empty by default, matched as an exact string — so it could not have
covered a gateway whose address Docker chooses.

**Why the score mattered more than it looked.** Eight more points and it bans.
Then every service refuses the host, `smoke-test.sh` starts failing for reasons
that have nothing to do with what it tests — and fail2ban's action is:

```
actionban = ufw insert 1 deny from <ip> to any
```

A deny rule against the bridge gateway cuts the host off from every container
it runs. The appliance would have firewalled itself away from itself, and the
symptom would have looked exactly like the nftables outage above: containers
unreachable, no obvious cause. This deployment was saved by not having `ufw`
installed, which is luck, not design.

**Fix.** The gateway is detected from `/proc/net/route` and ignored by default
(`HONEYPOT_IGNORE_GATEWAY=0` to opt out), rather than hardcoding a `172.x` that
would be wrong elsewhere. `HONEYPOT_IGNORE_IPS` now accepts CIDR ranges as well
as single addresses. The fail2ban jail also lists the Docker ranges in
`ignoreip` — a second lock on the same door, because the failure mode is losing
the whole stack rather than one service.

**Avoid it.** Ask what a safety mechanism does when it fires on the wrong
target. Scoring the host was untidy; *banning* it was the outage. A control
whose worst case is self-inflicted denial of service needs a floor under it
that does not depend on configuration nobody filled in.

---

## Every rickroll recording was an empty file, and there were 321 of them

**Symptom.** One banned address filled all five slots in the live feed, its
profile claimed 321 connections, and every recording was exactly 166 bytes.

**Cause.** Two independent problems that presented as one.

`rickroll.banner()` returns **bytes** — it is written to a raw socket. Both the
SSH and telnet ban paths passed it straight to `SessionRecorder.write_output()`,
which builds a frame with `json.dumps()`. That raises `TypeError` on bytes, and
the method's blanket `except Exception: pass` swallowed it. The frame was
dropped, the file kept its header, and 166 bytes is what an asciicast header
weighs. Both call sites carried a comment explaining that delivery was *finally*
being recorded. It never was, from the moment the feature was added.

Separately, the recording was created per connection. A banned scanner
reconnects every few seconds — 321 times in half an hour here — and is handed
the identical picture each time, so the feed filled with copies of one drawing
and the profile page tried to stitch a 321-segment playback of it.

**Why it hid.** The bug wrote a file, at a plausible path, with a valid header,
on schedule. Nothing errored, nothing was missing, and the dashboard listed the
sessions correctly — they were real files. Only the size gave it away, and only
because five of them were on screen at once showing the same number.

**Fix.** `_write()` decodes bytes rather than letting `json.dumps` refuse them,
so no raw-socket service can lose a frame this way again, and both call sites
decode explicitly. `rickroll.should_record()` limits recordings to one per
address per hour (`HONEYPOT_RICKROLL_RECORD_INTERVAL`). The drip still runs on
every connection and `log_hold` still counts every second — their time is the
point; the duplicate file is not.

**Avoid it.** A blanket `except Exception: pass` around a serialiser turns a
type error into missing data. If a write is worth doing, its failure is worth
distinguishing from its success — and "file exists, correct name, right size for
a header" is not evidence that anything was recorded.

---

## The tarpit was set on three services that never honoured it

**Symptom.** None, which is the problem. Addresses were marked tarpitted, the
dashboard said so, the events were logged — and the attackers kept getting fast
answers.

**Cause.** `activate_tarpit()` writes a flag. Honouring it is each service's
own job, and three of them never did:

| Service | What it did | What was missing |
|---|---|---|
| MySQL | called `activate_tarpit()` from five places in `answer_query()` | never imported `shared.tarpit` at all |
| SMTP | one `sleep` on EHLO, decided at connect | every later reply, and any re-check |
| FTP | delayed every reply correctly | never called `begin_hold()`, so holds were invisible live |

MySQL is the stark one: five call sites setting a flag, and no reader. An IP
tarpitted by SSH or SMB got a full-speed MySQL, and a `UNION SELECT` that
tarpitted an address in one breath was answered instantly in the next.

**Why it hid.** Everything *looked* right from outside the service. The flag was
set, the dashboard showed `TARPITTED`, `TARPIT_ENGAGED` was in the event log,
and the score was shared across services exactly as designed. The only way to
see it was to notice that nothing in `fake_mysqld.py` ever read the flag back —
absence of code, which no log line reports.

**Fix.** All three drain through `shared.tarpit` and register the hold. Verdicts
now come from what `score_named_event()` already returns rather than a fresh
lookup, so acting on them costs nothing.

**Avoid it.** A flag with no reader is not a feature. When state is written in
one module and honoured in another, the honouring is the part worth testing —
the writing will look fine either way.

---

## A ban only took effect on the attacker's next connection

**Symptom.** An attacker crosses the ban threshold with a reverse shell, and
carries on working in the shell they already have.

**Cause.** Every service checked `is_banned()` once, at connect. Nothing watched
the `banned` verdict that `score_named_event()` returns on every scored event —
which is precisely when a ban is earned, since the events worth banning for
(dropper, reverse shell, `authorized_keys`) all happen mid-session. The tarpit
had been given a mid-connection re-check; the ban never got the same treatment.

**Fix.** Each service reads the verdict it is already being handed, finishes the
reply to the command that crossed the line — that reply is the evidence — and
then closes. SSH and telnet wrap the scorer they pass to `FakeShell`; SMB, FTP,
SMTP and MySQL track it on the connection. RDP is one exchange with no loop, so
there is nothing to cut short.

---

## Every MySQL session ended on the same line

**Symptom.** Attackers connect, send one query, and are gone. Thirty-two
connections from one address, every recording ending at
`SELECT @@max_allowed_packet`. It reads like the honeypot hanging up on them.

**Cause.** Nothing hung up. That query is not the attacker's — it is what
libmysqlclient sends automatically once authentication finishes, and the client
does not display the answer, it *configures itself* from it. It had no handler,
so it fell through to the generic `SELECT` at the bottom of `answer_query()`:

```python
if low.startswith("select"):
    return result_set(["result"], [["1"]], 1)
```

A perfectly well-formed result set saying the server accepts one-byte packets.
The client believed it, concluded it could not send anything, and closed the
connection itself. The column name was wrong too — `result` rather than
`@@max_allowed_packet` — which breaks connectors that look results up by name.

**Why it hid.** The framing was never malformed, so nothing logged an error and
the packets look correct in a capture. The failure is entirely in the *meaning*
of a valid reply, and it happens before the attacker types anything, so the
recording of a killed session is indistinguishable from someone who lost
interest. Thirty-two identical short sessions read as a scanner's behaviour,
not as a bug.

**Fix.** A `SYSVARS` table answering the variables clients actually ask for,
returning columns named `@@<var>` and handling `@@session.`/`@@global.`
qualifiers and multi-variable selects. `SHOW VARIABLES` now answers from the
same table and honours `LIKE`, because older connectors probe that way instead.
The advertised `max_allowed_packet` is `MAX_PACKET` itself, so the number we
publish is the number `read_packet()` enforces.

**Avoid it.** A generic fallback that answers *plausibly* is more dangerous than
one that errors. `SELECT` → `1` looked harmless precisely because it was
well-formed. Where a protocol has a setup handshake, its questions deserve real
answers before any thought goes into the interesting ones.

---

## SMB sessions ended one command after they started

**Symptom.** Same report, different service: attackers connect, get through
`TREE_CONNECT`, and disappear.

**Cause.** Two independent walls, either one sufficient.

`CMD_CREATE` was defined as a constant and listed in `CMD_NAMES`, so it *looked*
handled — but there was no branch for it. It fell into the catch-all `else` and
got `STATUS_NOT_IMPLEMENTED`. CREATE is what every client sends immediately
after connecting to a share, because you cannot do anything to a share without
opening something on it. So the server accepted the share and then broke.

Behind that, every `NTLMSSP_AUTH` returned `STATUS_LOGON_FAILURE`
unconditionally. That is correct for capturing hashes and nothing else: a client
that cannot log in has no reason to keep talking, so most sessions never reached
the first wall.

**Why it hid.** The constant and the name in `CMD_NAMES` made CREATE read as
implemented at a glance, and the transcripts said `SMB2 CREATE` — the recorder
names the command from `CMD_NAMES` before dispatch, so the log showed the
command arriving whether or not anything handled it.

**Fix.** Implemented CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY, QUERY_INFO,
SET_INFO, FLUSH, LOCK, ECHO and CANCEL over a fake tree, so a client can browse.
Auth grants a guest session after the hash is captured — refusing again buys one
more spray attempt and loses every client that gives up after one failure.
`IOCTL` and `CHANGE_NOTIFY` answer `STATUS_NOT_SUPPORTED`, which a client
understands and moves past; the unhandled-command error was not.

Nothing an attacker writes touches a disk. WRITE is acknowledged, the first 64
bytes go into the transcript as evidence, and the rest is dropped.

**Avoid it.** A constant is not an implementation, and a name in a lookup table
is not either. Both made the transcript claim more than the code did.

---

## Stale nftables rules blackhole all container traffic

**Symptom.** Every container times out reaching Redis. Attacker profiles vanish
from the dashboard while the event feed keeps updating.

**Cause.** `bootstrap.sh` ran `netfilter-persistent save`, which snapshots every
iptables table — including the chains Docker owns and rewrites. Those name
bridges by interface, and bridge names change whenever a network is recreated.
Docker writes them with a **negated** match:

```
-A PREROUTING -d 172.25.0.2/32 ! -i br-4964bdc7466b -j DROP
```

While the bridge exists that reads "arrived from somewhere else" and is correct.
Once it is deleted, nothing can have arrived on it, so **the negation matches
everything** and a protective rule inverts into a blackhole. 6,725 packets were
dropped before anyone noticed.

**Why it took five wrong theories.** Every diagnostic pointed elsewhere:

| Observation | Why it misled |
|---|---|
| `iptables -L` shows nothing dropped | `raw` PREROUTING is not in that view |
| ARP resolves, bridge looks healthy | ARP is not IP; the rule cannot match it |
| The host reaches the container fine | Host traffic uses OUTPUT, not PREROUTING |
| `ACCEPT` at the top of `DOCKER-USER` changes nothing | The packet is already gone |
| `tcpdump` sees the SYN on the veth, nothing on the bridge | Dropped in between |

`sudo nft list ruleset` showed it in seconds. On any nft-backed host that should
be the *first* command when packets vanish without explanation.

**Fix.** Stopped persisting Docker's chains at all — Docker rebuilds them from
live networks at every start. `drosera-firewall.service` reinstalls only the
three `DOCKER-USER` rules that are ours, ordered after `docker.service`.
`clean-stale-nft.sh` removes leftovers; `smoke-test.sh` fails on them.

**Avoid it.** Stop the stack *before* touching the daemon, never after.

---

## logrotate emptied the history it was meant to keep

**Symptom.** Every past day in the stats picker reads zero. The days are listed;
they are just empty.

**Cause.** `storage/logs/*.jsonl` is already one file per UTC day — the rotation
has happened, by name. Pointing logrotate at it meant `copytruncate` copied each
finished day aside and **emptied the original in place**. `maxsize 100M` did the
same thing mid-day to a busy today.

**Fix.** Removed the stanza. Retention moved to `watchdog.sh`, which expires
whole days. `read_day()` reads the displaced `.1`/`.gz` siblings back, so
history returns on boxes that already ran the old policy — the data was never
deleted, only misfiled.

---

## The identity store failed silently, and slowly

**Symptom.** Nothing scored, tarpitted or banned for forty minutes. Dashboard
looked like a quiet day.

**Cause.** Two independent problems in the same function. Losing Redis produced
no signal at all — `iter_identities()` caught the error and returned empty, so
"cannot reach the database" rendered identically to "no attackers yet". And
`_client()` caches the connection, so once the server was gone **every call
still paid the full 3-second timeout** before falling back, on every connection
to every service. Slow enough to change how the honeypot behaves under load,
which is a deception failure on top of an availability one.

**Fix.** Fail open, loudly. `IDENTITY_STORE_DEGRADED` goes to the event log —
a file, so it works precisely when Redis does not — and to Telegram. The
dashboard shows a banner instead of an empty table. A circuit breaker opens
after three failures so calls short-circuit to the local fallback.

Failing *closed* was considered and rejected: refusing connections during an
outage turns a degraded honeypot into a dead one and discards data that is
still perfectly collectable.

---

## Attacker-minutes counted time nobody spent

**Symptom.** Tarpit totals slightly but consistently too high.

**Cause.** `held` was measured to the moment the failure surfaced, not to the
last byte the client accepted. A client that disconnects during one of the
sleeps is not discovered until the next send raises — so up to twelve seconds
per connection were credited to the tarpit having cost an attacker nothing.
Across ~7,000 SSH holds that is hours of imaginary time.

**Fix.** Track the last successful write and measure to that.

The web tarpit was always correct here: it checks `connection_aborted()` each
chunk and logs real elapsed.

---

## The interesting paths were the ones that returned early

**Symptom.** Sessions = 0 on the attackers with the most activity. No recording
of the rickroll ever.

**Cause.** Three separate branches created their recorder *after* an early
return. The SSH tarpit path had no recorder at all — 117 of 147 held hours
producing nothing. Telnet created one after the hold, and the client usually
gave up during it, so the following write failed and execution never reached
the recorder. Both ban/rickroll branches returned before any recorder existed.

Self-reinforcing, too: once an address crossed the threshold every subsequent
connection took the tarpit path, so recordings stopped exactly when the
attacker became interesting.

**Fix.** Recorder opens before the branch, in all of them.

---

## Lifetime stats silently under-reported past 80,000 events

**Cause.** `day_facts()` went through `read_day()`, which caps at 80,000 events
to bound what a page render can allocate. Correct for a page, wrong for an
aggregate: a busy day crossing the cap under-reported every all-time figure with
nothing on screen to say so. The busiest day was already at 34,413.

**Fix.** `day_facts()` streams and holds only the sets, so there is no ceiling.

---

## The persona stopped at the company name

**Symptom.** Every deployment's fake site was byte-identical below the title.

**Cause.** `{{COMPANY_NAME}}` was substituted, but the tagline, meta
description, `<h1>`, phone number and entity suffix were hardcoded. A search for
`"Expert IT Solutions for Modern Business"` plus `(512) 555-0123` fingerprinted
every install at once — and the phone number contradicted the address whenever
the generated city was not Austin. The copyright was frozen at `2024`, so every
site advertised itself as two years abandoned.

**Fix.** Tagline, keywords, phone (area code matched to the generated city),
entity suffix and current year all come from the persona. The generator's
required-key check now fails loudly on an old persona rather than falling back
to the shipped defaults, which would reintroduce the shared fingerprint.

---

## wget reported DNS failure for an address it never resolved

**Cause.** The fake shell emitted `Resolving 31.56.209.153 ... Temporary failure
in name resolution` for an IP literal. Real `wget` goes straight to
`Connecting to`. The common case, too — Mirai-family loaders hardcode addresses
precisely to avoid depending on DNS.

**Fix.** IP literals now produce a connection failure. `curl` likewise returns
exit 7 (failed to connect) rather than 6 (could not resolve).

---

## Smaller ones

- **`icc: false`** removed from the daemon config. It only ever governed
  `docker0`, which this deployment does not use, while being able to become the
  inherited default for a user-defined bridge created afterwards. Networks now
  state `enable_icc` explicitly. *(Investigated as a cause of the outage above.
  It was not.)*
- **IP columns sorted lexically**, putting `9.0.0.1` after `100.0.0.1` and
  interleaving every /8. Now sorted by octet.
- **Tarpit state sampled once per connection**, so an address pushed over the
  threshold mid-session — including by a different service, since the score is
  shared — kept getting fast answers until it reconnected. SMB now acts on the
  verdict `score_named_event()` already returns.
- **Countries counted `unknown` as a country**, so a day of un-geolocated
  traffic reported "1 country" beside a top country of "—".
- **Site licence** said MIT. It is PolyForm Noncommercial, which prohibits
  commercial use — a materially different claim to publish.
