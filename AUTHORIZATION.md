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
| **Uploads are discarded.** File content is hashed for evidence, then dropped. Nothing attacker-supplied is written to disk. | FTP `STOR`, SFTP sink, PHP upload handler |
| **Not an open relay.** The SMTP honeypot advertises relaying and accepts messages, but no SMTP client is ever opened and nothing is delivered. It cannot send mail. | `smtp-honey/fake_smtpd.py` |
| **No outbound network capability.** Honeypot containers sit on an `internal` Docker network with no egress. The box cannot be used as a pivot or proxy. | `docker-compose.yml` |
| **Nothing can be staged or run.** Read-only root filesystem, `noexec,nosuid,nodev` on every writable path, all capabilities dropped, `no-new-privileges`, setuid binaries stripped at build. Code execution inside a container has nowhere to write, nowhere to execute from, and no way to fetch a payload. | `docker-compose.yml`, all Dockerfiles |
| **Captured credentials are evidence, never used.** NTLM responses and password attempts are logged for attribution. Nothing authenticates anywhere with them. | `shared/identity.py` `record_credential()` |
| **Tarpits are bounded.** Concurrency caps and hard time limits prevent the tarpit from becoming a self-DoS or an amplification vector. | `TARPIT_MAX_CONCURRENT`, `TARPIT_MAX_SECONDS` |

The tarpit slows *inbound* connections that the attacker initiated. It sends no
unsolicited traffic and generates no amplification — it is the opposite of a
DoS tool.

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
