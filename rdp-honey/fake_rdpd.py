"""Fake RDP listener speaking X.224 / TPKT.

Parses the Connection Request for the mstshash cookie (RDP clients put the
attempted username there) and answers with an RDP Negotiation Failure, which is
what a real host without a TLS certificate returns.
"""

import asyncio
import binascii
import os
import re
import struct
import sys

sys.path.insert(0, "/app")

from shared import alerting, identity, tarpit  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "33389"))
SERVICE = "rdp"

IDLE_TIMEOUT = int(os.getenv("RDP_IDLE_TIMEOUT", "60"))
TARPIT_MAX_SECONDS = int(os.getenv("RDP_TARPIT_MAX_SECONDS", "600"))
MAX_PDU = 65535

TPKT_VERSION = 3
X224_CR = 0xE0
X224_CC = 0xD0

RDP_NEG_REQ, RDP_NEG_RSP, RDP_NEG_FAILURE = 0x01, 0x02, 0x03
SSL_CERT_NOT_ON_SERVER = 0x00000002

COOKIE_RE = re.compile(rb"Cookie:\s*mstshash=([^\r\n]{0,128})", re.I)
TOKEN_RE = re.compile(rb"Cookie:\s*msts=([^\r\n]{0,128})", re.I)

PROTOCOL_NAMES = {
    0x00000000: "RDP (legacy)",
    0x00000001: "TLS",
    0x00000002: "CredSSP/NLA",
    0x00000004: "RDSTLS",
    0x00000008: "CredSSP with Early User Auth",
}


async def read_tpkt(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    if header[0] != TPKT_VERSION:
        raise ConnectionResetError("not TPKT")
    length = struct.unpack(">H", header[2:4])[0]
    if length < 4 or length > MAX_PDU:
        raise ConnectionResetError("bad TPKT length")
    return header + await reader.readexactly(length - 4)


def connection_confirm(failure_code: int = SSL_CERT_NOT_ON_SERVER) -> bytes:
    negotiation = struct.pack("<BBHI", RDP_NEG_FAILURE, 0, 8, failure_code)
    x224 = struct.pack(">BBHHB", 6 + len(negotiation), X224_CC, 0, 0x1234, 0) + negotiation
    return struct.pack(">BBH", TPKT_VERSION, 0, 4 + len(x224)) + x224


def parse_connection_request(pdu: bytes) -> dict:
    """Pull the cookie, routing token, and requested security protocols."""
    info = {"cookie": "", "routing_token": "", "requested_protocols": None}

    match = COOKIE_RE.search(pdu)
    if match:
        info["cookie"] = match.group(1).decode("utf-8", "replace")
    token = TOKEN_RE.search(pdu)
    if token:
        info["routing_token"] = token.group(1).decode("utf-8", "replace")

    index = pdu.find(b"\r\n")
    offset = index + 2 if index >= 0 else 11
    if len(pdu) >= offset + 8 and pdu[offset] == RDP_NEG_REQ:
        try:
            info["requested_protocols"] = struct.unpack("<I", pdu[offset + 4:offset + 8])[0]
        except struct.error:
            pass
    return info


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip = peer[0]

    if identity.is_banned(ip):
        writer.close()
        return

    identity.get_or_create_identity(ip)

    # RDP is binary, so its recording can only be a written account of the
    # negotiation. That is still worth having: without one this service and SMB
    # were the only two whose sessions never appeared on the dashboard and were
    # missing from every evidence bundle.
    recorder = alerting.SessionRecorder(ip, SERVICE, title=f"rdp from {ip}")
    recorder.write_output(f"RDP connection from {ip}\r\n")

    try:
        pdu = await asyncio.wait_for(read_tpkt(reader), timeout=IDLE_TIMEOUT)

        if len(pdu) < 6 or pdu[5] != X224_CR:
            recorder.write_output("non-X.224 probe; dropping\r\n")
            identity.score_named_event(
                ip, "RDP_CONNECT", payload="non-X.224 probe", service=SERVICE)
            writer.close()
            return

        info = parse_connection_request(pdu)
        protocols = info["requested_protocols"]
        protocol_label = PROTOCOL_NAMES.get(protocols, f"0x{protocols:08x}") \
            if protocols is not None else "unspecified"

        recorder.write_output(
            f"X.224 Connection Request\r\n"
            f"  mstshash: {info['cookie'] or '(none)'}\r\n"
            f"  protocols: {protocol_label}\r\n")
        identity.score_named_event(
            ip, "RDP_CONNECT",
            payload=f"mstshash={info['cookie']} protocols={protocol_label}"[:200],
            service=SERVICE,
        )
        if info["cookie"]:
            username = info["cookie"]
            domain = ""
            if "\\" in username:
                domain, _, username = username.partition("\\")
            identity.record_credential(ip, f"{domain}\\{username}" if domain else username,
                                       "", SERVICE)

        alerting.alert_event(
            ip=ip, event_type="RDP_CONNECTION_REQUEST", service=SERVICE,
            reason=f"X.224 CR requesting {protocol_label}",
            payload=binascii.hexlify(pdu[:96]).decode(),
            rdp_cookie=info["cookie"],
            rdp_routing_token=info["routing_token"],
            rdp_requested_protocols=protocol_label,
        )

        if identity.is_tarpitted(ip):
            # Trickle the Connection Confirm out a byte at a time instead of
            # sleeping. A flat delay is something a scanner waits out once; an
            # incomplete TPKT header keeps it blocked on read for as long as we
            # care to hold it, because it cannot know the PDU has not arrived.
            identity.score_named_event(ip, "TARPIT_ENGAGED", payload="rdp tarpit",
                                       service=SERVICE)
            recorder.write_output("tarpit: dripping Connection Confirm\r\n")
            held = await tarpit.drip(writer, connection_confirm(),
                                     tarpit.deadline(TARPIT_MAX_SECONDS))
            tarpit.log_hold(ip, SERVICE, held)
            recorder.write_output(f"tarpit held this connection {held:.0f}s\r\n")
        else:
            recorder.write_output("-> Connection Confirm (negotiation failure)\r\n")
            writer.write(connection_confirm())
            await writer.drain()

        # Anything sent after the failure is logged, then we drop the connection.
        try:
            extra = await asyncio.wait_for(reader.read(4096), timeout=10)
        except asyncio.TimeoutError:
            extra = b""
        if extra:
            recorder.write_output(
                f"client sent {len(extra)} more byte(s) after the failure\r\n")
            alerting.alert_event(
                ip=ip, event_type="RDP_POST_NEGOTIATION", service=SERVICE,
                reason="Client continued after negotiation failure",
                payload=binascii.hexlify(extra[:200]).decode(),
            )
    except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError,
            ConnectionResetError, struct.error):
        pass
    finally:
        recorder.write_output("session closed\r\n")
        recorder.close()
        try:
            writer.close()
        except OSError:
            pass


async def main() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    print(f"[*] fake rdpd listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
