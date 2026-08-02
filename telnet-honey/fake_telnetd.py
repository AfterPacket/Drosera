#!/usr/bin/env python3
"""Fake telnetd with IAC negotiation, login trap, and fake shell.

A client that never answers our IAC negotiation is almost certainly an automated
scanner rather than a terminal, so we fingerprint that and score it.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, "/app")

from shared import (alerting, crash, credentials, identity, nmap, persona,  # noqa: E402
                    rickroll, scoring, tarpit)
from shared.fakeshell import FakeShell  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "2323"))
SERVICE = "telnet"

TARPIT_LOGIN_DELAY = float(os.getenv("TELNET_TARPIT_DELAY", "30.0"))
IDLE_TIMEOUT = int(os.getenv("TELNET_IDLE_TIMEOUT", "300"))
MAX_LINE = 512

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_ECHO, OPT_SGA = 1, 3


async def read_line(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    echo: bool = True, timeout: int = IDLE_TIMEOUT) -> str:
    """Read one line, stripping telnet IAC sequences and handling backspace."""
    buffer = bytearray()
    while len(buffer) < MAX_LINE:
        chunk = await asyncio.wait_for(reader.read(1), timeout=timeout)
        if not chunk:
            raise ConnectionResetError
        byte = chunk[0]

        if byte == IAC:
            verb = await asyncio.wait_for(reader.read(1), timeout=timeout)
            if not verb:
                raise ConnectionResetError
            if verb[0] in (DO, DONT, WILL, WONT):
                await asyncio.wait_for(reader.read(1), timeout=timeout)
            elif verb[0] == SB:
                while True:
                    nxt = await asyncio.wait_for(reader.read(1), timeout=timeout)
                    if not nxt or nxt[0] == SE:
                        break
            continue

        if byte in (10, 13):
            if byte == 13:
                # Consume a paired LF or NUL without blocking on a bare CR.
                try:
                    await asyncio.wait_for(reader.read(1), timeout=0.05)
                except asyncio.TimeoutError:
                    pass
            if echo:
                writer.write(b"\r\n")
                await writer.drain()
            return buffer.decode("utf-8", "replace")

        if byte in (8, 127):
            if buffer:
                buffer.pop()
                if echo:
                    writer.write(b"\b \b")
                    await writer.drain()
            continue

        buffer.append(byte)
        if echo:
            writer.write(bytes([byte]))
            await writer.drain()

    return buffer.decode("utf-8", "replace")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip = peer[0]

    if identity.is_banned(ip):
        # Telnet is a raw byte stream with no negotiation owed to anyone, so
        # this is the one service where the art lands exactly as drawn.
        # Dripped, so the ban path costs them time rather than just closing.
        art = rickroll.banner()
        if art:
            # Recorded like everything else. This branch returns before the
            # normal recorder is created, so the delivery -- the one moment an
            # operator actually wants to watch -- was the only thing the
            # honeypot never kept.
            #
            # Rate-limited: a banned address reconnects constantly and gets the
            # identical picture each time, so recording every delivery buries
            # the live feed under copies of one drawing. The drip still runs on
            # every connection.
            recorder = None
            if rickroll.should_record(ip):
                recorder = alerting.SessionRecorder(
                    ip, SERVICE, title=f"telnet rickroll from {ip}")
                # Decoded: the art is bytes for the socket, and a recorder
                # frame is JSON, which has no way to carry raw bytes.
                recorder.write_output(art.decode("utf-8", "replace"))
            hold_key = tarpit.begin_hold(ip, SERVICE, rickroll.DRIP_SECONDS)
            try:
                held = await tarpit.drip(
                    writer, art, tarpit.deadline(int(rickroll.DRIP_SECONDS)),
                    byte_delay=rickroll.drip_delay(art))
            finally:
                tarpit.end_hold(hold_key)
            if recorder is not None:
                recorder.write_output(f"\r\ndelivered over {held:.0f}s\r\n")
                recorder.close()
            tarpit.log_hold(ip, SERVICE, held, reason="telnet rickroll (banned)")
        writer.close()
        return

    ident = identity.get_or_create_identity(ip)
    identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)
    recorder = None

    # Check for crash mode before any telnet negotiation
    if identity.is_crashed(ip):
        crash_response = crash.telnet_crash()
        try:
            writer.write(crash_response)
            await writer.drain()
            tarpit.log_hold(ip, SERVICE, 0.1, reason="telnet crash mode")
        except (OSError, asyncio.TimeoutError):
            pass
        writer.close()
        return

    try:
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_ECHO]))
        await writer.drain()

        # A real terminal answers negotiation promptly; scanners usually do not.
        # Bound before the read, not inside it: a client that connects and sends
        # nothing is the single most common case here, and it leaves the name
        # unassigned on the timeout path that every line below then reads.
        probe = b""
        negotiated = False
        try:
            probe = await asyncio.wait_for(reader.read(64), timeout=3)
            negotiated = bool(probe) and IAC in probe
        except asyncio.TimeoutError:
            pass
        if not negotiated:
            identity.score_named_event(
                ip, "TOOL_OTHER", payload="no IAC response (non-terminal client)",
                tool="Automated telnet client", service=SERVICE,
            )
            # nmap's telnet service probes name the tool in what they send. The
            # banner test, not the path test: a telnet client sends no request
            # path, so is_nmap_probe_path() could only ever have been false here.
            # Detection only -- the address is not scanned back, see shared/nmap.py.
            if nmap.is_nmap_useragent(probe.decode("latin-1", "replace")):
                result = identity.score_named_event(
                    ip, "TOOL_NMAP", payload=probe[:200].decode("latin-1", "replace"),
                    tool="nmap", service=SERVICE,
                )
                if crash.enabled() and scoring.should_crash(float(result.get("new_score") or 0)):
                    identity.activate_crash(ip, reason="nmap detected", service=SERVICE)

        # Opened above the tarpit, not below it. A held client usually gives up
        # during the stall, and the write that follows then fails on a dead
        # socket -- so execution never reached the recorder and the connection
        # left no transcript at all. Held-and-abandoned is thin evidence, but it
        # is evidence, and it was the most common outcome for exactly the
        # addresses worth having evidence on.
        recorder = alerting.SessionRecorder(ip, SERVICE, title=f"telnet from {ip}")

        if identity.is_tarpitted(ip):
            identity.score_named_event(ip, "TARPIT_ENGAGED",
                                       payload="telnet tarpit", service=SERVICE)
            recorder.write_output("telnet tarpit engaged\r\n")
            started = time.monotonic()
            hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_LOGIN_DELAY)
            try:
                await asyncio.sleep(TARPIT_LOGIN_DELAY)
            finally:
                tarpit.end_hold(hold_key)
                recorder.write_output(
                    f"held {time.monotonic() - started:.0f}s\r\n")
                # Logged even when the client gives up mid-hold, which is the
                # normal case and the whole point -- the time is spent whether
                # or not they wait for the end of it. Without this the stall
                # happened but never appeared in "attacker-minutes wasted",
                # which counted only SSH, SMB and RDP.
                tarpit.log_hold(ip, SERVICE, time.monotonic() - started)

        hostname = ident.get("fake_hostname", "srv-01")
        banner = f"\r\n{ident.get('fake_os', 'Ubuntu 22.04.3 LTS')}\r\n"
        writer.write(banner.encode())
        await writer.drain()
        recorder.write_output(banner)

        username = ""
        authenticated = False
        for _ in range(3):
            prompt = f"{hostname} login: "
            writer.write(prompt.encode())
            await writer.drain()
            username = (await read_line(reader, writer)).strip()
            recorder.write_output(prompt + username + "\r\n")

            writer.write(b"Password: ")
            await writer.drain()
            password = (await read_line(reader, writer, echo=False)).strip()
            writer.write(b"\r\n")
            await writer.drain()
            # Shown in the clear where the wire masks it: this is evidence, not
            # the attacker's terminal, and the credential is the capture.
            recorder.write_output(f"Password: {password}\r\n")

            identity.record_credential(ip, username, password, SERVICE)
            identity.score_named_event(
                ip, "CREDENTIAL_ATTEMPT",
                payload=f"{username}:{password}"[:200], service=SERVICE,
            )
            if identity.detect_spray(ip):
                identity.score_named_event(ip, "CREDENTIAL_SPRAY", service=SERVICE)
                identity.activate_tarpit(ip, "Telnet credential spray", SERVICE)

            if identity.is_banned(ip):
                writer.write(b"Login incorrect\r\n")
                await writer.drain()
                recorder.write_output("Login incorrect\r\n")
                return

            # A generated credential cannot exist on a real machine, so
            # accepting one says the box accepts anything. Refused here, and
            # the loop asks again -- which is what a real login does, and gives
            # a spray somewhere to keep spending its wordlist.
            if not credentials.accepts(username, password):
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
                recorder.write_output("Login incorrect\r\n")
                username = ""
                continue
            authenticated = True
            break

        # Falling out of the loop used to land in the shell regardless, which
        # would have made the refusal above pure theatre -- three rejections and
        # then a prompt anyway is a stranger thing to find than a box that
        # accepts everything.
        if not authenticated:
            writer.write(b"\r\nMaximum number of tries exceeded\r\n")
            await writer.drain()
            recorder.write_output("Maximum number of tries exceeded\r\n")
            return

        username = username or "root"

        motd = (f"Welcome to {ident.get('fake_os', 'Ubuntu 22.04.3 LTS')} "
                f"(GNU/Linux {ident.get('fake_kernel', '5.15.0-86-generic')} x86_64)\r\n\r\n"
                f"Last login: {persona.get('last_login_at')} "
                f"from {persona.get('last_login_from')} on pts/0\r\n")
        writer.write(motd.encode())
        await writer.drain()
        recorder.write_output(motd)

        # The ban is checked once at login, which covers a credential spray but
        # not the shell -- and the shell is where the events that actually earn
        # a ban happen. Wrapping the scorer catches the verdict FakeShell is
        # already being handed, without a second Redis lookup per command.
        session_banned = False

        def score(target_ip, event_type, *args, **kwargs):
            nonlocal session_banned
            result = identity.score_named_event(target_ip, event_type,
                                                *args, **kwargs)
            if isinstance(result, dict) and result.get("banned"):
                session_banned = True
            return result

        shell = FakeShell(ip, ident, score=score,
                          service=SERVICE, username=username)

        loop = asyncio.get_running_loop()
        while not shell.exit_requested:
            prompt = shell.prompt()
            writer.write(prompt.encode())
            await writer.drain()
            recorder.write_output(prompt)

            line = await read_line(reader, writer)
            recorder.write_input(line + "\n")
            if not line.strip():
                continue

            # FakeShell's latency tiers block; keep them off the event loop.
            output = await loop.run_in_executor(None, shell.run, line)
            if output:
                payload = output.replace("\n", "\r\n") + "\r\n"
                writer.write(payload.encode())
                await writer.drain()
                recorder.write_output(payload)

            # Show them the output of the command that crossed the line -- it
            # is the evidence, and it is already scored -- then end the session.
            if session_banned:
                recorder.write_output("Connection closed by foreign host.\r\n")
                break
    except (OSError, asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        if recorder is not None:
            recorder.close()
        try:
            writer.close()
        except OSError:
            pass


async def main() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    print(f"[*] fake telnetd listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
