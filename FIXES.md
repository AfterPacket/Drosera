# Notable fixes

Bugs whose cause was not where the symptom pointed. Kept because the reasoning
is worth more than the diff — several of these were expensive to find, and the
next one will look just as innocent.

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
