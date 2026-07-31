#!/usr/bin/env python3
"""Fake Postfix ESMTP. Advertises an open relay, accepts mail, delivers nothing.

Zero-trust: message bodies are truncated into the evidence log and dropped. No
SMTP client is ever opened, so this cannot be used to actually send mail.
"""

import asyncio
import base64
import binascii
import os
import sys
import time

sys.path.insert(0, "/app")

from shared import alerting, identity, persona, tarpit  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "2525"))
SERVICE = "smtp"

TARPIT_BANNER_DELAY = float(os.getenv("SMTP_TARPIT_DELAY", "10.0"))
IDLE_TIMEOUT = int(os.getenv("SMTP_IDLE_TIMEOUT", "300"))
TARPIT_MAX_SECONDS = int(os.getenv("SMTP_TARPIT_MAX_SECONDS", "600"))
MAX_LINE = 4096
MAX_MESSAGE_BYTES = 262144
LOCAL_DOMAINS = (persona.get("company_domain"), "localhost")


def _b64(value: str) -> str:
    try:
        return base64.b64decode(value + "===", validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return value


class SMTPSession:
    def __init__(self, ip: str, hostname: str):
        self.ip = ip
        self.hostname = hostname
        self.mail_from = ""
        self.rcpt_to = []
        self.helo = ""
        self.auth_pending = None
        self.auth_username = ""


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip = peer[0]

    if identity.is_banned(ip):
        writer.close()
        return

    ident = identity.get_or_create_identity(ip)
    identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)
    session = SMTPSession(ip, ident.get("fake_hostname", "mail-srv-01"))

    # SMTP is a line protocol, so the transcript replays as a readable terminal
    # session directly. Created up front rather than lazily: unlike SSH, every
    # SMTP connection gets a banner, so there is no empty-recording case.
    recorder = alerting.SessionRecorder(ip, SERVICE, title=f"smtp from {ip}")

    # The tarpit used to be one sleep on EHLO, decided once at connect. That
    # left two gaps: a relay probe that earned the tarpit with its own RCPT was
    # answered at full speed for the rest of the session, and the hold never
    # showed up under "Held right now" because it was a bare sleep rather than
    # a registered hold. Both are fixed by draining inside send().
    state = {"tarpitted": identity.is_tarpitted(ip), "banned": False}
    hold_until = tarpit.deadline(TARPIT_MAX_SECONDS)
    held = 0.0
    hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS) \
        if state["tarpitted"] else None

    def engage() -> None:
        nonlocal hold_key
        if not state["tarpitted"]:
            state["tarpitted"] = True
            recorder.write_output("[tarpit engaged]\r\n")
        if hold_key is None:
            hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)

    def score(event_type: str, payload: str = ""):
        """Score, and honour the verdict this reply rather than the next one."""
        result = identity.score_named_event(ip, event_type, payload=payload,
                                            service=SERVICE)
        if result.get("tarpitted"):
            engage()
        if result.get("banned"):
            state["banned"] = True
        return result

    async def send(line: str) -> None:
        nonlocal held
        if state["tarpitted"]:
            held += await tarpit.stall(hold_until)
        recorder.write_output(line + "\r\n")
        writer.write((line + "\r\n").encode())
        await writer.drain()

    try:
        await send(f"220 mail.{session.hostname} ESMTP {persona.get('smtp_software')}")

        while True:
            try:
                raw = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                await send("421 4.4.2 Timeout, closing transmission channel")
                break
            if not raw:
                break
            line = raw[:MAX_LINE].decode("utf-8", "replace").strip()
            if not line:
                continue
            recorder.write_output(line + "\r\n")

            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            arg = arg.strip()

            if session.auth_pending:
                await _handle_auth_continuation(session, line, send, score)
                if state["banned"]:
                    recorder.write_output("[banned mid-session, closing]\r\n")
                    break
                continue

            if verb in ("EHLO", "HELO"):
                session.helo = arg
                # An open-relay probe usually stalls here; make it expensive.
                # send() drains every line after this too -- and an EHLO reply
                # is ten capability lines, so it is already the costliest
                # command -- but the pause up front is a fixed, configured one,
                # so it stays an explicit sleep rather than a random stall.
                if state["tarpitted"]:
                    pause = min(TARPIT_BANNER_DELAY,
                                max(0.0, hold_until - time.time()))
                    if pause > 0:
                        started = time.monotonic()
                        try:
                            await asyncio.sleep(pause)
                        finally:
                            held += time.monotonic() - started
                if verb == "EHLO":
                    for cap in (f"250-mail.{session.hostname}", "250-PIPELINING",
                                "250-SIZE 52428800", "250-VRFY", "250-ETRN",
                                "250-STARTTLS", "250-AUTH LOGIN PLAIN",
                                "250-ENHANCEDSTATUSCODES", "250-8BITMIME",
                                "250 DSN"):
                        await send(cap)
                else:
                    await send(f"250 mail.{session.hostname}")

            elif verb == "AUTH":
                await _handle_auth_start(session, arg, send, score)

            elif verb == "MAIL":
                session.mail_from = arg
                session.rcpt_to = []
                await send("250 2.1.0 Ok")

            elif verb == "RCPT":
                session.rcpt_to.append(arg)
                target = arg.lower()
                is_remote = not any(d in target for d in LOCAL_DOMAINS)
                if is_remote:
                    score("SMTP_RELAY",
                          payload=f"{session.mail_from} -> {arg}"[:200])
                    identity.activate_tarpit(ip, "SMTP open relay probe", SERVICE)
                    engage()
                await send("250 2.1.5 Ok")

            elif verb == "DATA":
                if not session.rcpt_to:
                    await send("503 5.5.1 Error: need RCPT command")
                    continue
                await send("354 End data with <CR><LF>.<CR><LF>")
                body = await _read_message(reader)
                alerting.alert_event(
                    ip=ip, event_type="SMTP_MESSAGE", service=SERVICE,
                    reason="Message accepted and discarded",
                    payload=body[:500],
                    mail_from=session.mail_from,
                    rcpt_to=session.rcpt_to[:20],
                    message_bytes=len(body),
                )
                await send("250 2.0.0 Ok: queued as " +
                           binascii.hexlify(os.urandom(6)).decode().upper())
                session.mail_from = ""
                session.rcpt_to = []

            elif verb == "STARTTLS":
                # We have no cert to offer and never want a real TLS session here.
                await send("454 4.7.0 TLS not available due to temporary reason")

            elif verb == "VRFY":
                await send("252 2.0.0 Cannot VRFY user")

            elif verb == "RSET":
                session.mail_from = ""
                session.rcpt_to = []
                await send("250 2.0.0 Ok")

            elif verb == "NOOP":
                await send("250 2.0.0 Ok")

            elif verb == "QUIT":
                await send("221 2.0.0 Bye")
                break

            else:
                await send(f"502 5.5.2 Error: command not recognized")

            # The reply that crossed the threshold is already sent and
            # recorded; the connection goes no further.
            if state["banned"]:
                recorder.write_output("[banned mid-session, closing]\r\n")
                break
    except (OSError, asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        tarpit.end_hold(hold_key)
        tarpit.log_hold(ip, SERVICE, held)
        if held:
            recorder.write_output(f"[tarpit held this connection {held:.0f}s]\r\n")
        recorder.close()
        try:
            writer.close()
        except OSError:
            pass


async def _handle_auth_start(session: SMTPSession, arg: str, send, score) -> None:
    mechanism, _, initial = arg.partition(" ")
    mechanism = mechanism.upper()

    if mechanism == "PLAIN":
        if initial:
            _record_plain(session, initial, score)
            await send("235 2.7.0 Authentication successful")
        else:
            session.auth_pending = "PLAIN"
            await send("334 ")
    elif mechanism == "LOGIN":
        session.auth_pending = "LOGIN_USER"
        await send("334 VXNlcm5hbWU6")
    else:
        await send("504 5.5.4 Unrecognized authentication type")


async def _handle_auth_continuation(session: SMTPSession, line: str, send,
                                    score) -> None:
    stage = session.auth_pending

    if stage == "PLAIN":
        session.auth_pending = None
        _record_plain(session, line, score)
        await send("235 2.7.0 Authentication successful")
    elif stage == "LOGIN_USER":
        session.auth_username = _b64(line)
        session.auth_pending = "LOGIN_PASS"
        await send("334 UGFzc3dvcmQ6")
    elif stage == "LOGIN_PASS":
        session.auth_pending = None
        password = _b64(line)
        _record(session, session.auth_username, password, score)
        await send("235 2.7.0 Authentication successful")
    else:
        session.auth_pending = None
        await send("501 5.5.2 Cannot decode response")


def _record_plain(session: SMTPSession, blob: str, score) -> None:
    """SASL PLAIN is authzid\\0authcid\\0password."""
    decoded = _b64(blob)
    parts = decoded.split("\x00")
    username = parts[1] if len(parts) > 2 else (parts[0] if parts else "")
    password = parts[2] if len(parts) > 2 else ""
    _record(session, username, password, score)


def _record(session: SMTPSession, username: str, password: str, score) -> None:
    """`score` is the connection's scorer, so a spray is honoured on the spot.

    These used to call identity.score_named_event directly and drop what it
    returned, which meant the one branch a password spray actually lives in
    could tarpit or ban an address without the connection doing anything
    differently -- the next connection got the slow treatment, this one did not.
    """
    identity.record_credential(session.ip, username, password, SERVICE)
    score("CREDENTIAL_ATTEMPT", f"{username}:{password}"[:200])
    if identity.detect_spray(session.ip):
        score("CREDENTIAL_SPRAY")
        identity.activate_tarpit(session.ip, "SMTP credential spray", SERVICE)


async def _read_message(reader: asyncio.StreamReader) -> str:
    """Read until the lone-dot terminator, bounded so we cannot be memory-flooded."""
    chunks = []
    total = 0
    while total < MAX_MESSAGE_BYTES:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            break
        if not raw:
            break
        if raw.strip() == b".":
            break
        total += len(raw)
        chunks.append(raw)
    return b"".join(chunks).decode("utf-8", "replace")


async def main() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    print(f"[*] fake smtpd listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
