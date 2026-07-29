#!/usr/bin/env python3
"""Fake SMB server on 445 (SMB2) and 139 (NetBIOS/SMB1).

Answers NEGOTIATE, issues an NTLM challenge on SESSION_SETUP, and accepts every
TREE_CONNECT so share enumeration looks successful. Captured NTLMv2 responses are
reassembled into hashcat-format lines as evidence -- nothing is ever verified or
used to authenticate anywhere.
"""

import asyncio
import binascii
import os
import struct
import sys
import time

sys.path.insert(0, "/app")

from shared import alerting, identity, persona, tarpit  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
PORT_SMB = int(os.getenv("LISTEN_PORT_SMB", "4445"))
PORT_NBT = int(os.getenv("LISTEN_PORT_NBT", "4139"))
SERVICE = "smb"

IDLE_TIMEOUT = int(os.getenv("SMB_IDLE_TIMEOUT", "120"))
TARPIT_MAX_SECONDS = int(os.getenv("SMB_TARPIT_MAX_SECONDS", "600"))
MAX_PDU = 1 << 20

SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"

CMD_NEGOTIATE, CMD_SESSION_SETUP, CMD_LOGOFF = 0x0000, 0x0001, 0x0002
CMD_TREE_CONNECT, CMD_TREE_DISCONNECT, CMD_CREATE = 0x0003, 0x0004, 0x0005

# For the session transcript. SMB is binary, so a recording of it can only ever
# be a written account of what happened -- but "what happened" is the part an
# operator reads anyway, and without one this service was the only one whose
# sessions were invisible on the dashboard and absent from evidence bundles.
CMD_NAMES = {
    CMD_NEGOTIATE: "NEGOTIATE",
    CMD_SESSION_SETUP: "SESSION_SETUP",
    CMD_LOGOFF: "LOGOFF",
    CMD_TREE_CONNECT: "TREE_CONNECT",
    CMD_TREE_DISCONNECT: "TREE_DISCONNECT",
    CMD_CREATE: "CREATE",
}

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D

SERVER_GUID = os.urandom(16)
# Fixed so every captured NTLMv2 line is crackable against a known challenge.
SERVER_CHALLENGE = bytes.fromhex(os.getenv("SMB_NTLM_CHALLENGE", "1122334455667788"))
NTLM_TARGET = str(persona.get("company_slug")).upper()[:15] or "WORKGROUP"

SHARES = {"IPC$": 0x02, "C$": 0x01, "ADMIN$": 0x01, "SharedDocs": 0x01, "backups": 0x01}


def filetime(when: float) -> int:
    """Unix epoch seconds -> Windows FILETIME (100ns since 1601)."""
    return int((when + 11644473600) * 10_000_000)


def smb2_header(command: int, message_id: int, status: int = STATUS_SUCCESS,
                tree_id: int = 0, session_id: int = 0, credits: int = 1) -> bytes:
    return (
        SMB2_MAGIC
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", credits)
        + struct.pack("<I", 0x00000001)   # SMB2_FLAGS_SERVER_TO_REDIR
        + struct.pack("<I", 0)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0)
        + struct.pack("<I", tree_id)
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )


def negotiate_response(message_id: int) -> bytes:
    now = filetime(time.time())
    body = (
        struct.pack("<H", 65)
        + struct.pack("<H", 0x0001)       # signing enabled
        + struct.pack("<H", 0x0210)       # dialect SMB 2.1
        + struct.pack("<H", 0)
        + SERVER_GUID
        + struct.pack("<I", 0x00000001)   # DFS
        + struct.pack("<I", 0x00100000)
        + struct.pack("<I", 0x00100000)
        + struct.pack("<I", 0x00100000)
        + struct.pack("<Q", now)
        + struct.pack("<Q", filetime(time.time() - 4_060_800))
        + struct.pack("<H", 128)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
    )
    return smb2_header(CMD_NEGOTIATE, message_id) + body


def ntlm_challenge_blob() -> bytes:
    # NTLM target name -- the Windows domain this box claims to be joined to.
    # Enumeration tools print it, so it belongs to the persona like every other
    # observable name.
    target = NTLM_TARGET.encode("utf-16le")
    payload_offset = 56
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target), len(target), payload_offset)
        + struct.pack("<I", 0xE2898235)
        + SERVER_CHALLENGE
        + b"\x00" * 8
        + struct.pack("<HHI", len(target), len(target), payload_offset + len(target))
        + b"\x06\x03\x80\x25\x00\x00\x00\x0f"
        + target
        + target
    )


def session_setup_response(message_id: int, session_id: int, blob: bytes,
                           status: int = STATUS_MORE_PROCESSING) -> bytes:
    body = (struct.pack("<H", 9) + struct.pack("<H", 0)
            + struct.pack("<H", 64 + 8) + struct.pack("<H", len(blob)) + blob)
    return smb2_header(CMD_SESSION_SETUP, message_id, status,
                       session_id=session_id) + body


def tree_connect_response(message_id: int, session_id: int, tree_id: int,
                          share_type: int) -> bytes:
    body = (struct.pack("<H", 16) + bytes([share_type]) + b"\x00"
            + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<I", 0x001F01FF))
    return smb2_header(CMD_TREE_CONNECT, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def error_response(command: int, message_id: int, status: int,
                   session_id: int = 0) -> bytes:
    return (smb2_header(command, message_id, status, session_id=session_id)
            + struct.pack("<H", 9) + b"\x00" * 7)


def parse_ntlm_auth(blob: bytes, ip: str) -> None:
    """Pull username/domain and the NTLMv2 response out of an AUTHENTICATE message."""
    index = blob.find(b"NTLMSSP\x00")
    if index < 0:
        return
    body = blob[index:]
    if len(body) < 64 or struct.unpack("<I", body[8:12])[0] != 3:
        return

    def field(offset: int):
        length, _, position = struct.unpack("<HHI", body[offset:offset + 8])
        return body[position:position + length]

    try:
        nt_response = field(20)
        domain = field(28).decode("utf-16le", "replace")
        user = field(36).decode("utf-16le", "replace")
        workstation = field(44).decode("utf-16le", "replace")
    except (struct.error, IndexError):
        return

    hashline = ""
    if len(nt_response) > 24:
        proof = binascii.hexlify(nt_response[:16]).decode()
        rest = binascii.hexlify(nt_response[16:]).decode()
        hashline = (f"{user}::{domain}:{SERVER_CHALLENGE.hex()}:{proof}:{rest}")

    identity.record_credential(ip, f"{domain}\\{user}", hashline[:200], SERVICE)
    identity.score_named_event(
        ip, "CREDENTIAL_ATTEMPT",
        payload=f"NTLMv2 {domain}\\{user} from {workstation}"[:200], service=SERVICE,
    )
    alerting.alert_event(
        ip=ip, event_type="SMB_NTLM_CAPTURE", service=SERVICE,
        reason=f"NTLMv2 response captured for {domain}\\{user}",
        payload=hashline[:500], ntlm_user=user, ntlm_domain=domain,
        ntlm_workstation=workstation,
    )


async def read_nbt(reader: asyncio.StreamReader):
    """NetBIOS session service framing: 1 byte type, 3 byte length, then payload."""
    header = await reader.readexactly(4)
    msg_type = header[0]
    length = int.from_bytes(header[1:4], "big")
    if length > MAX_PDU:
        raise ConnectionResetError("oversized PDU")
    return msg_type, await reader.readexactly(length)


def wrap_nbt(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 netbios: bool = False) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip = peer[0]

    if identity.is_banned(ip):
        writer.close()
        return

    identity.get_or_create_identity(ip)
    identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)

    session_id = int.from_bytes(os.urandom(6), "little") or 1
    tree_counter = 1
    trees = {}

    recorder = alerting.SessionRecorder(ip, SERVICE, title=f"smb from {ip}")
    recorder.write_output(
        f"SMB session from {ip} on {'139/netbios' if netbios else '445'}\r\n")

    # Share enumeration is chatty -- an SMB client sends NEGOTIATE, SESSION_SETUP
    # and a TREE_CONNECT per share. Delaying each response turns a scan that took
    # under a second into one that takes minutes, and SMB clients wait patiently
    # because a slow file server is completely ordinary.
    tarpitted = identity.is_tarpitted(ip)
    hold_until = tarpit.deadline(TARPIT_MAX_SECONDS)
    held = 0.0
    hold_key = None
    if tarpitted:
        identity.score_named_event(ip, "TARPIT_ENGAGED", payload="smb tarpit",
                                   service=SERVICE)
        hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)

    try:
        while True:
            try:
                msg_type, payload = await asyncio.wait_for(
                    read_nbt(reader), timeout=IDLE_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break

            # NetBIOS session request on 139 -> positive session response.
            if netbios and msg_type == 0x81:
                recorder.write_output("NetBIOS session request -> accepted\r\n")
                writer.write(b"\x82\x00\x00\x00")
                await writer.drain()
                continue

            if payload.startswith(SMB1_MAGIC):
                recorder.write_output("SMB1 NEGOTIATE -> steering client to SMB2\r\n")
                identity.score_named_event(
                    ip, "SMB_ENUM", payload="SMB1 negotiate", service=SERVICE)
                # Steer SMB1 clients to SMB2 by answering the wildcard dialect.
                writer.write(wrap_nbt(negotiate_response(0)))
                await writer.drain()
                continue

            if not payload.startswith(SMB2_MAGIC) or len(payload) < 64:
                break

            command, = struct.unpack("<H", payload[12:14])
            message_id, = struct.unpack("<Q", payload[24:32])
            body = payload[64:]
            recorder.write_output(
                f"SMB2 {CMD_NAMES.get(command, f'0x{command:04x}')}\r\n")

            alerting.alert_event(
                ip=ip, event_type="SMB_PDU", service=SERVICE,
                reason=f"SMB2 command 0x{command:04x}",
                payload=binascii.hexlify(payload[:96]).decode(),
                smb_command=command,
            )

            if command == CMD_NEGOTIATE:
                identity.score_named_event(ip, "SMB_ENUM",
                                           payload="SMB2 NEGOTIATE", service=SERVICE)
                writer.write(wrap_nbt(negotiate_response(message_id)))

            elif command == CMD_SESSION_SETUP:
                blob = body[24:] if len(body) > 24 else b""
                if b"NTLMSSP\x00" in blob and len(blob) > 20:
                    index = blob.find(b"NTLMSSP\x00")
                    msg = struct.unpack("<I", blob[index + 8:index + 12])[0] \
                        if len(blob) >= index + 12 else 1
                    if msg == 3:
                        recorder.write_output("  NTLMSSP_AUTH -> STATUS_LOGON_FAILURE\r\n")
                        parse_ntlm_auth(blob, ip)
                        # Slow the failure too: this is the branch a password
                        # spray hits over and over, so it is the one where a
                        # delay costs the attacker the most.
                        if tarpitted:
                            held += await tarpit.stall(hold_until)
                        writer.write(wrap_nbt(error_response(
                            CMD_SESSION_SETUP, message_id, STATUS_LOGON_FAILURE,
                            session_id)))
                        await writer.drain()
                        continue
                writer.write(wrap_nbt(session_setup_response(
                    message_id, session_id, ntlm_challenge_blob())))

            elif command == CMD_TREE_CONNECT:
                share = ""
                try:
                    offset, length = struct.unpack("<HH", body[4:8])
                    raw = payload[offset:offset + length]
                    share = raw.decode("utf-16le", "replace")
                except (struct.error, IndexError):
                    pass
                leaf = share.rstrip("\\").split("\\")[-1] or "IPC$"
                recorder.write_output(f"  share {share or leaf}\r\n")
                identity.score_named_event(
                    ip, "SMB_ENUM", payload=f"TREE_CONNECT {share}"[:200],
                    service=SERVICE)
                tree_counter += 1
                trees[tree_counter] = leaf
                writer.write(wrap_nbt(tree_connect_response(
                    message_id, session_id, tree_counter,
                    SHARES.get(leaf, 0x01))))

            elif command == CMD_TREE_DISCONNECT:
                writer.write(wrap_nbt(
                    smb2_header(CMD_TREE_DISCONNECT, message_id, session_id=session_id)
                    + struct.pack("<H", 4) + b"\x00\x00"))

            elif command == CMD_LOGOFF:
                writer.write(wrap_nbt(
                    smb2_header(CMD_LOGOFF, message_id, session_id=session_id)
                    + struct.pack("<H", 4) + b"\x00\x00"))
                await writer.drain()
                break

            else:
                writer.write(wrap_nbt(error_response(
                    command, message_id, 0xC0000002, session_id)))

            if tarpitted:
                held += await tarpit.stall(hold_until)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError, ConnectionResetError, struct.error):
        pass
    finally:
        tarpit.end_hold(hold_key)
        tarpit.log_hold(ip, SERVICE, held)
        if held:
            recorder.write_output(f"tarpit held this connection {held:.0f}s\r\n")
        recorder.write_output("session closed\r\n")
        recorder.close()
        try:
            writer.close()
        except OSError:
            pass


async def main() -> None:
    smb = await asyncio.start_server(
        lambda r, w: handle(r, w, netbios=False), LISTEN_HOST, PORT_SMB)
    nbt = await asyncio.start_server(
        lambda r, w: handle(r, w, netbios=True), LISTEN_HOST, PORT_NBT)
    print(f"[*] fake smbd listening on {LISTEN_HOST}:{PORT_SMB} (SMB2) "
          f"and :{PORT_NBT} (NetBIOS)", flush=True)
    async with smb, nbt:
        await asyncio.gather(smb.serve_forever(), nbt.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
