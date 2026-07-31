# Authorization, Ethics, and Legal Basis

This document records the basis on which the Drosera honeypot appliance is built
and operated. Keep it with the deployment. If a hosting provider, upstream ISP,
CERT, or auditor ever asks what this box is, this is the answer.

---

## 1. Nature of the work

Drosera is a **defensive deception system** — a honeypot. Its purpose is to
detect, characterise, and record unauthorised access attempts against
infrastructure the operator controls, and to waste the resources of automated
scanners through tarpitting.

This is established defensive security practice, in the same category as
Cowrie, Dionaea, T-Pot, OpenCanary, and Thinkst Canary. It is detection
engineering and threat intelligence work, not offensive tooling.

Honeypots look superficially like attacker infrastructure because they *emulate*
attacker-facing services. The distinction that matters is capability: see §4.

## 2. Operator attestation

Fill in before deployment and keep the completed copy.

This repository ships the blank template. Fill in your own copy on the
deployment and keep it there — do not commit a completed attestation to a public
repository, since it ties a named individual to a live honeypot and lists its
address.

| Field | Value |
|---|---|
| Operator | _________________ |
| Role | _________________ |
| Deployment date | _________________ |
| VPS provider / instance ID | _________________ |
| Public IP(s) | _________________ |
| Domain name | _________________ |
| Domain registrar account holder | _________________ |
| Provider ToS reviewed for honeypot operation | ☐ yes, date: __________ |

The operator attests that:

1. The VPS is **owned or lawfully leased** by the operator, and is dedicated
   solely to this deployment.
2. The domain is **registered to or lawfully controlled by** the operator.
3. No third-party system, network, or data is targeted, scanned, or accessed by
   this deployment.
4. The deployment is **passive**: it responds to inbound connections only. It
   never initiates contact with any external host except the optional alerting
   channels the operator explicitly configures (§6).
5. The operator has reviewed the hosting provider's acceptable-use policy.
   Most providers permit honeypots; some require notification. Confirm before
   deploying.

### 2.1 Whether to tell your hosting provider

Short answer: **read their AUP, and do not volunteer this document.**

This file is written to be *produced on request* — by a provider, an upstream
ISP, or law enforcement — not to be sent unprompted. Emailing a legal and ethics
document to a general support queue means a first-line agent skims it, sees
"honeypot", "malware" and "captured credentials", and escalates to abuse. You
have created a ticket where there was none, and handed a human the decision on
something they would otherwise never have examined. Providers that permit this
by default need no convincing; providers that do not will now refuse in writing,
which is worse than not asking, because it converts future operation into a
knowing violation rather than an unexamined one.

Notify anyway in two cases:

1. **You are enabling payload quarantine.** `storage/loot/` holds live malware
   samples. Many acceptable-use policies prohibit storing malicious binaries
   regardless of intent, and providers run scanners that will find them. Clear
   this in advance: the failure mode is termination without warning, and it
   takes your evidence with it.
2. **The policy is ambiguous, or mentions honeypots or security research at
   all.** If it says notify, notify. If it is silent, silence is normally
   permission.

When you do notify, send three sentences, not this file:

> I am running a honeypot on instance `<id>` — emulated services that log
> unauthorised connection attempts. It has no outbound connectivity, hosts
> nothing real, and serves no production traffic. I have documentation of the
> legal basis and data-handling controls available if you would like it.

The last clause is the point. It offers this document without requiring anyone
to read it: if they want it they will ask, and you are then answering a question
rather than making a disclosure.

Expect abuse complaints eventually regardless — not from your traffic, which
never leaves the box, but from scanned parties misreading their own logs, or
from an attacker's provider replying to a report you filed. §7 and §8 cover
that, and that is the moment this document earns its keep.

## 3. Why a honeypot is lawful to run

- **You may run whatever services you like on your own host.** Emulating an FTP
  banner on your own VPS is no more regulated than running a real FTP server.
- **No unauthorised access occurs.** Every connection is inbound and
  unsolicited. The operator accesses nobody else's system.
- **Entrapment does not apply.** Entrapment is a defence against *government*
  inducement to commit a crime. A private operator running a passive service
  cannot entrap. Nothing here solicits, advertises, or invites intrusion; the
  system merely fails to repel it.
- **Deceptive content is not fraud.** Fabricated hostnames, fake credentials,
  and a fictional company create no reliance interest in anyone lawfully using
  the system, because no one lawfully uses the system.

Note the honeypot-specific caveat: **no legitimate traffic should ever reach
this machine.** That is the design premise — see "Core principle" in
`README.md`. Do not host anything real on this box, and do not point a domain at
it that anyone has a legitimate reason to visit.

## 4. Design safeguards — what makes this non-weaponizable

These are enforced in code, not just policy. They are the substantive answer to
"is this actually defensive?"

| Safeguard | Where enforced |
|---|---|
| **Nothing attacker-supplied is ever executed.** No `exec`/`system`/`shell_exec`/`popen`/`eval` on any input, in any language. All "command execution" is table-driven string simulation. | `shared/fakeshell.py`, `web/lib/drosera.php`, PHP `disable_functions` |
| **No real filesystem access from attacker input.** Fake paths resolve against an in-Redis tree, never a real path. | `FakeShell._resolve()` / `_node()` |
| **No real SQL.** The MySQL honeypot pattern-matches queries and returns static tables. No database is ever connected. | `mysql-honey/fake_mysqld.py` |
| **Uploads are quarantined, never served.** Payloads are hashed and written to `storage/loot/<sha256>.bin`, mode `0400`, with a `.bin` suffix and no execute bit. They are evidence, and are handled as such — see the containment trace below. | `shared/loot.py`, FTP `STOR`, SFTP sink, PHP upload handler |
| **Quarantine is write-only from the attacker's side.** There is no code path by which a stored payload can be read back out through any emulated service. Audited line by line; the trace is below this table. | `shared/fakeshell.py`, `ssh-honey/fake_sshd.py`, `ftp-honey/fake_ftpd.py`, `nginx/honeypot.conf` |
| **Not an open relay.** The SMTP honeypot advertises relaying and accepts messages, but no SMTP client is ever opened and nothing is delivered. It cannot send mail. | `smtp-honey/fake_smtpd.py` |
| **No outbound network capability.** Honeypot containers sit on an `internal` Docker network with no egress. The box cannot be used as a pivot or proxy. | `docker-compose.yml` |
| **Nothing can be staged or run.** Read-only root filesystem, `noexec,nosuid,nodev` on every writable path, all capabilities dropped, `no-new-privileges`, setuid binaries stripped at build. Code execution inside a container has nowhere to write, nowhere to execute from, and no way to fetch a payload. | `docker-compose.yml`, all Dockerfiles |
| **Captured credentials are evidence, never used.** NTLM responses and password attempts are logged for attribution. Nothing authenticates anywhere with them. | `shared/identity.py` `record_credential()` |
| **Tarpits are bounded.** Concurrency caps and hard time limits prevent the tarpit from becoming a self-DoS or an amplification vector. | `TARPIT_MAX_CONCURRENT`, `TARPIT_MAX_SECONDS` |

The tarpit slows *inbound* connections that the attacker initiated. It sends no
unsolicited traffic and generates no amplification — it is the opposite of a
DoS tool.

### 4.1 Quarantine containment

The deployment stores real malware. Whether that is defensible rests on one
claim: **nothing an attacker can reach can read it back.** Every path by which
a stored byte could travel outward, and what stops it:

| Route | What happens |
|---|---|
| Fake shell `cat`, `head`, any read | `shared/fakeshell.py` performs **no real filesystem reads at all** — no `open()`, no `Path()`. The filesystem it presents is generated and held in Redis |
| SFTP read | `SFTPServerInterface.open()` returns `SFTP_PERMISSION_DENIED` unless the mode is a write, and writes go to quarantine |
| FTP `RETR` | Sends generated bytes; never opens a file |
| HTTP | nginx: `location ^~ /storage { deny all; return 404; }` |
| Dashboard `/clips/`, `/sessions/` | `Path(name).name` strips traversal, and a suffix allowlist (`.gif`/`.mp4`, `.cast`) makes `.bin` unreachable. Both require authentication |
| Anything else reading `LOOT_DIR` | Only the authenticated evidence export and `intel/vt.py`. **No honeypot container reads it** |
| The container that fetches | `intel` sits alone on `cam-egress`, listens on nothing, and shares no network with any honeypot |

At rest the file is mode `0400`, owned by a non-root user, on a mount carrying
`noexec,nosuid,nodev`, in a container with a read-only root filesystem and all
capabilities dropped. It is never parsed, decompressed or inspected — only
hashed.

If second-stage retrieval is enabled (`FETCH_ENABLED`, off by default), the
fetched payload enters this same quarantine by the same function and is subject
to every line above. What changes is *provenance*, not handling: the bytes are
pulled rather than pushed, which is a disclosure and legal question (§2.1),
not a containment one.

## 5. Data protection

The system records attacker IP addresses, credentials they submit, and session
transcripts. In the EU/UK, an IP address is personal data, so consider:

- **Lawful basis:** legitimate interest — network and information security.
  GDPR Recital 49 explicitly names this as a legitimate interest.
- **Data minimisation:** payload excerpts are capped (500 chars in alerts,
  1000 in request logs); session recordings are capped at
  `HONEYPOT_MAX_SESSION_BYTES`.
- **Retention:** set a retention period and enforce it with `RETENTION_DAYS` in
  `deploy/watchdog.sh`, which expires whole days of event log on every run
  (logrotate covers the evidence and audit logs only). Identity records expire
  automatically after 7 days (`IDENTITY_TTL`); bans after `HONEYPOT_BAN_TTL`.
  Decide and document a retention period for JSONL logs and `.cast` files.
  **Recommended: 90 days**, unless a specific incident warrants preservation.
- **Third-party credentials:** attackers frequently submit credentials belonging
  to *other* victims (reused from prior breaches). Treat the credential store as
  sensitive. Do not publish it. Do not test captured credentials anywhere.
- **Access control:** the dashboard requires password + TOTP and binds to
  localhost only, reachable via SSH tunnel. Evidence exports leave the box only
  when the operator downloads them.

Interception/wiretap statutes (US ECPA, UK IPA, etc.) generally permit a system
operator to monitor traffic on their own service for security purposes. Because
every session here is with the honeypot itself — not a third party's
communications passing through — this is provider monitoring of its own systems,
not interception.

## 6. Outbound alerting

The honeypot network has **no egress by default**. Webhook, Telegram, and remote
syslog alerting are implemented but inert until the operator enables egress
explicitly. If enabled:

- Alert payloads contain attacker IPs and payload excerpts — treat the
  destination as a system that receives personal data.
- Telegram alerting sends data to a third-party service outside your control.
  Prefer webhook-to-your-own-endpoint or syslog if that matters to you.

## 7. Sharing intelligence

If sharing indicators (IPs, hashes, TTPs) with AbuseIPDB, a CERT, an ISAC, or
your provider's abuse desk:

- Share indicators and behaviour. Do not share captured third-party credentials.
- Reporting an attacking IP to its provider's abuse contact is normal and
  encouraged.
- **Do not retaliate.** No scanning back, no counter-exploitation, no
  "hack-back". That is unlawful in essentially every jurisdiction and the
  architecture deliberately makes it impossible from this box.

## 8. Incident escalation

If the honeypot captures evidence of a serious compromise elsewhere (e.g. an
attacker reveals credentials or infrastructure belonging to a third-party
victim), the appropriate action is to notify the affected party or a CERT — not
to investigate further yourself.

Evidence packages (`/api/export/<ip>`) bundle the event log, session recordings,
and a summary suitable for handing to a provider abuse desk or law enforcement.

---

**Summary:** this is a passive, self-contained, non-weaponizable detection
system on infrastructure the operator controls. It attacks nothing, relays
nothing, executes nothing, and reaches out to nothing.
