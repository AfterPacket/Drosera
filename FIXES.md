# Notable fixes

Bugs whose cause was not where the symptom pointed. Kept because the reasoning
is worth more than the diff — several of these were expensive to find, and the
next one will look just as innocent.

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
