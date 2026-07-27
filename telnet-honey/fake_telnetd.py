#!/usr/bin/env python3
"""Fake telnetd with IAC negotiation, login trap, and fake shell.

A client that never answers our IAC negotiation is almost certainly an automated
scanner rather than a terminal, so we fingerprint that and score it.
"""

import asyncio
import os
import sys

sys.path.insert(0, "/app")

from shared import alerting, identity  # noqa: E402
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
        writer.close()
        return

    ident = identity.get_or_create_identity(ip)
    identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)
    recorder = None

    try:
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_ECHO]))
        await writer.drain()

        # A real terminal answers negotiation promptly; scanners usually do not.
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

        if identity.is_tarpitted(ip):
            identity.score_named_event(ip, "TARPIT_ENGAGED",
                                       payload="telnet tarpit", service=SERVICE)
            await asyncio.sleep(TARPIT_LOGIN_DELAY)

        hostname = ident.get("fake_hostname", "srv-01")
        writer.write(f"\r\n{ident.get('fake_os', 'Ubuntu 22.04.3 LTS')}\r\n".encode())
        await writer.drain()

        # Opened before the login loop, not after it. Most telnet bots submit
        # one credential and disconnect without ever reaching a shell, so
        # starting the recording after authentication meant the only thing they
        # did was the one thing never captured.
        recorder = alerting.SessionRecorder(ip, SERVICE, title=f"telnet from {ip}")

        username = ""
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
            break

        username = username or "root"

        motd = (f"Welcome to {ident.get('fake_os', 'Ubuntu 22.04.3 LTS')} "
                f"(GNU/Linux {ident.get('fake_kernel', '5.15.0-86-generic')} x86_64)\r\n\r\n"
                f"Last login: Mon Jan 15 08:14:02 UTC 2024 from 10.0.1.9 on pts/0\r\n")
        writer.write(motd.encode())
        await writer.drain()
        recorder.write_output(motd)

        shell = FakeShell(ip, ident, score=identity.score_named_event,
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
