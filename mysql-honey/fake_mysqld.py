#!/usr/bin/env python3
"""Fake mysqld speaking enough of protocol v10 to satisfy real clients and sqlmap.

Zero-trust: no SQL is parsed into anything executable. Queries are pattern-matched
and answered from static tables, and the only "delay" honored is a bounded
asyncio.sleep that makes time-based blind injection feel authentic.
"""

import asyncio
import os
import re
import struct
import sys

sys.path.insert(0, "/app")

from shared import alerting, identity  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "33306"))
SERVICE = "mysql"

SERVER_VERSION = os.getenv("FAKE_MYSQL_VERSION", "5.7.38-0ubuntu0.22.04.1")
MAX_SLEEP_SECONDS = float(os.getenv("MYSQL_MAX_SLEEP", "10"))
IDLE_TIMEOUT = int(os.getenv("MYSQL_IDLE_TIMEOUT", "300"))
MAX_PACKET = 1 << 20

COM_QUIT, COM_INIT_DB, COM_QUERY, COM_PING = 0x01, 0x02, 0x03, 0x0E

CLIENT_PROTOCOL_41 = 0x00000200
SERVER_STATUS_AUTOCOMMIT = 0x0002

TYPE_VAR_STRING = 0xFD
TYPE_LONGLONG = 0x08

SLEEP_RE = re.compile(r"\b(?:sleep|benchmark)\s*\(\s*(\d+)", re.I)
UNION_RE = re.compile(r"\bunion\b.{0,80}?\bselect\b", re.I | re.S)
BLIND_RE = re.compile(r"\b(and|or)\b\s+\d+\s*=\s*\d+|\bif\s*\(|\bcase\s+when\b", re.I)
OUTFILE_RE = re.compile(r"\binto\s+(?:dump|out)file\b", re.I)
LOADFILE_RE = re.compile(r"\bload_file\s*\(|\bload\s+data\b", re.I)
XPCMD_RE = re.compile(r"\bxp_cmdshell\b", re.I)


# ------------------------------------------------------------------ encoding

def lenenc_int(value: int) -> bytes:
    if value < 251:
        return bytes([value])
    if value < 1 << 16:
        return b"\xfc" + struct.pack("<H", value)
    if value < 1 << 24:
        return b"\xfd" + struct.pack("<I", value)[:3]
    return b"\xfe" + struct.pack("<Q", value)


def lenenc_str(value: str) -> bytes:
    raw = value.encode("utf-8", "replace")
    return lenenc_int(len(raw)) + raw


def packet(payload: bytes, sequence: int) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([sequence & 0xFF]) + payload


def ok_packet(sequence: int, affected: int = 0, insert_id: int = 0,
              info: str = "") -> bytes:
    payload = (b"\x00" + lenenc_int(affected) + lenenc_int(insert_id)
               + struct.pack("<HH", SERVER_STATUS_AUTOCOMMIT, 0))
    if info:
        payload += info.encode()
    return packet(payload, sequence)


def err_packet(sequence: int, code: int, state: str, message: str) -> bytes:
    payload = (b"\xff" + struct.pack("<H", code) + b"#" + state.encode()
               + message.encode("utf-8", "replace"))
    return packet(payload, sequence)


def eof_packet(sequence: int) -> bytes:
    return packet(b"\xfe" + struct.pack("<HH", 0, SERVER_STATUS_AUTOCOMMIT), sequence)


def column_def(name: str, table: str = "", col_type: int = TYPE_VAR_STRING,
               length: int = 255) -> bytes:
    return (lenenc_str("def") + lenenc_str("wordpress") + lenenc_str(table)
            + lenenc_str(table) + lenenc_str(name) + lenenc_str(name)
            + b"\x0c" + struct.pack("<H", 33) + struct.pack("<I", length)
            + bytes([col_type]) + struct.pack("<H", 0) + b"\x00" + b"\x00\x00")


def result_set(columns, rows, sequence: int, table: str = "") -> bytes:
    out = packet(lenenc_int(len(columns)), sequence)
    sequence += 1
    for name in columns:
        out += packet(column_def(name, table), sequence)
        sequence += 1
    out += eof_packet(sequence)
    sequence += 1
    for row in rows:
        payload = b"".join(
            b"\xfb" if cell is None else lenenc_str(str(cell)) for cell in row
        )
        out += packet(payload, sequence)
        sequence += 1
    out += eof_packet(sequence)
    return out


def handshake(connection_id: int) -> bytes:
    salt1 = os.urandom(8)
    salt2 = os.urandom(12)
    capabilities = 0x000FF7FF | CLIENT_PROTOCOL_41
    payload = (
        b"\x0a"
        + SERVER_VERSION.encode() + b"\x00"
        + struct.pack("<I", connection_id)
        + salt1 + b"\x00"
        + struct.pack("<H", capabilities & 0xFFFF)
        + bytes([33])
        + struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
        + struct.pack("<H", (capabilities >> 16) & 0xFFFF)
        + bytes([21])
        + b"\x00" * 10
        + salt2 + b"\x00"
        + b"mysql_native_password\x00"
    )
    return packet(payload, 0)


# ------------------------------------------------------------------ queries

FAKE_TABLES = [
    "wp_commentmeta", "wp_comments", "wp_links", "wp_options", "wp_postmeta",
    "wp_posts", "wp_term_relationships", "wp_term_taxonomy", "wp_termmeta",
    "wp_terms", "wp_usermeta", "wp_users",
]

FAKE_USERS = [
    (1, "admin", "$P$BqZ7vK2nR8xLmYcD4wF6tG9hJ1sA0e/", "admin@meridiandigital.example",
     "Site Administrator"),
    (2, "jmarsh", "$P$B4kL9mN2pQ7rS5tU8vW1xY3zA6bC0d.", "jmarsh@meridiandigital.example",
     "Jordan Marsh"),
    (3, "editor", "$P$BvX2cV5bN8mQ1wE4rT7yU0iO3pA6sD/", "editor@meridiandigital.example",
     "Content Editor"),
]


async def answer_query(ip: str, sql: str) -> bytes:
    """Return the wire bytes for one COM_QUERY. Sequence always restarts at 1."""
    stripped = sql.strip().rstrip(";")
    low = stripped.lower()

    if OUTFILE_RE.search(low):
        identity.score_named_event(ip, "SQLI_OOB", payload=stripped[:300], service=SERVICE)
        identity.score_named_event(ip, "FILE_UPLOAD", payload=stripped[:300], service=SERVICE)
        identity.activate_tarpit(ip, "SQL INTO OUTFILE", SERVICE)
        return err_packet(1, 1290, "HY000",
                          "The MySQL server is running with the --secure-file-priv "
                          "option so it cannot execute this statement")

    if LOADFILE_RE.search(low):
        identity.score_named_event(ip, "SQLI_OOB", payload=stripped[:300], service=SERVICE)
        identity.activate_tarpit(ip, "SQL LOAD_FILE/LOAD DATA", SERVICE)
        return err_packet(1, 1290, "HY000",
                          "The MySQL server is running with the --secure-file-priv "
                          "option so it cannot execute this statement")

    if XPCMD_RE.search(low):
        identity.score_named_event(ip, "SQLI_OOB", payload=stripped[:300], service=SERVICE)
        return err_packet(1, 1305, "42000",
                          "PROCEDURE wordpress.xp_cmdshell does not exist")

    match = SLEEP_RE.search(low)
    if match:
        identity.score_named_event(ip, "SQLI_UNION_BLIND",
                                   payload=stripped[:300], service=SERVICE)
        identity.activate_tarpit(ip, "Time-based blind SQLi", SERVICE)
        # Honor the delay so timing oracles agree, but never unbounded.
        await asyncio.sleep(min(float(match.group(1)), MAX_SLEEP_SECONDS))
        return result_set(["SLEEP(%s)" % match.group(1)], [[0]], 1)

    if UNION_RE.search(low):
        identity.score_named_event(ip, "SQLI_UNION_BLIND",
                                   payload=stripped[:300], service=SERVICE)
        identity.activate_tarpit(ip, "UNION SQLi", SERVICE)
        columns = max(1, low.count(",") + 1)
        return result_set([f"col{i + 1}" for i in range(columns)],
                          [[None] * columns], 1)

    if BLIND_RE.search(low) and "select" in low:
        identity.score_named_event(ip, "SQLI_BASIC", payload=stripped[:300], service=SERVICE)
        identity.activate_tarpit(ip, "Boolean SQLi", SERVICE)

    if low.startswith("show databases"):
        return result_set(["Database"],
                          [["information_schema"], ["mysql"], ["performance_schema"],
                           ["sys"], ["wordpress"]], 1)

    if low.startswith("show tables"):
        return result_set(["Tables_in_wordpress"], [[t] for t in FAKE_TABLES], 1)

    if low.startswith("show grants"):
        return result_set(
            ["Grants for wp_user@localhost"],
            [["GRANT ALL PRIVILEGES ON `wordpress`.* TO 'wp_user'@'localhost'"]], 1)

    if low.startswith("grant "):
        return ok_packet(1)

    if low.startswith(("show variables", "show session variables", "show global variables")):
        return result_set(["Variable_name", "Value"], [
            ["version", SERVER_VERSION],
            ["version_comment", "(Ubuntu)"],
            ["character_set_server", "utf8mb4"],
            ["datadir", "/var/lib/mysql/"],
            ["secure_file_priv", "/var/lib/mysql-files/"],
            ["hostname", "prod-db-01"],
        ], 1)

    if "information_schema.tables" in low:
        identity.score_named_event(ip, "RECON_LS", payload=stripped[:300], service=SERVICE)
        return result_set(["table_schema", "table_name"],
                          [["wordpress", t] for t in FAKE_TABLES], 1)

    if "information_schema.schemata" in low:
        return result_set(["schema_name"],
                          [["information_schema"], ["mysql"], ["wordpress"]], 1)

    if "wp_users" in low:
        identity.score_named_event(ip, "SQLI_BASIC", payload=stripped[:300], service=SERVICE)
        return result_set(
            ["ID", "user_login", "user_pass", "user_email", "display_name"],
            [list(row) for row in FAKE_USERS], 1, table="wp_users")

    if low.startswith("select") and ("version()" in low or "@@version" in low):
        return result_set(["version()"], [[SERVER_VERSION]], 1)

    if low.startswith("select") and ("user()" in low or "current_user" in low):
        return result_set(["user()"], [["wp_user@localhost"]], 1)

    if low.startswith("select") and "database()" in low:
        return result_set(["database()"], [["wordpress"]], 1)

    if low.startswith("select"):
        return result_set(["result"], [["1"]], 1)

    if low.startswith(("set ", "use ", "commit", "rollback", "begin")):
        return ok_packet(1)

    if low.startswith(("insert", "update", "delete", "create", "drop", "alter")):
        return ok_packet(1, affected=1)

    return err_packet(1, 1064, "42000",
                      "You have an error in your SQL syntax; check the manual that "
                      "corresponds to your MySQL server version for the right syntax "
                      f"to use near '{stripped[:40]}' at line 1")


# ------------------------------------------------------------------- server

async def read_packet(reader: asyncio.StreamReader):
    header = await reader.readexactly(4)
    length = int.from_bytes(header[:3], "little")
    if length > MAX_PACKET:
        raise ConnectionResetError("oversized packet")
    return await reader.readexactly(length), header[3]


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip = peer[0]

    if identity.is_banned(ip):
        writer.close()
        return

    identity.get_or_create_identity(ip)
    identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)

    try:
        writer.write(handshake(os.getpid() & 0xFFFF))
        await writer.drain()

        response, _ = await asyncio.wait_for(read_packet(reader), timeout=30)
        username, auth_blob = parse_handshake_response(response)
        identity.record_credential(ip, username, auth_blob.hex()[:64], SERVICE)
        identity.score_named_event(
            ip, "CREDENTIAL_ATTEMPT",
            payload=f"{username}:<auth {auth_blob.hex()[:32]}>", service=SERVICE,
        )
        if identity.detect_spray(ip):
            identity.score_named_event(ip, "CREDENTIAL_SPRAY", service=SERVICE)
            identity.activate_tarpit(ip, "MySQL credential spray", SERVICE)

        writer.write(ok_packet(2))
        await writer.drain()

        while True:
            try:
                payload, _ = await asyncio.wait_for(read_packet(reader),
                                                   timeout=IDLE_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break
            if not payload:
                break

            command = payload[0]
            if command == COM_QUIT:
                break
            if command == COM_PING:
                writer.write(ok_packet(1))
                await writer.drain()
                continue
            if command == COM_INIT_DB:
                writer.write(ok_packet(1))
                await writer.drain()
                continue
            if command != COM_QUERY:
                writer.write(ok_packet(1))
                await writer.drain()
                continue

            sql = payload[1:].decode("utf-8", "replace")
            alerting.alert_event(
                ip=ip, event_type="SQL_QUERY", service=SERVICE,
                reason="COM_QUERY received", payload=sql[:500],
            )
            writer.write(await answer_query(ip, sql))
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError,
            ConnectionResetError, struct.error):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


def parse_handshake_response(payload: bytes):
    """Extract username and auth response from a protocol-41 handshake response."""
    try:
        offset = 32  # capabilities(4) max_packet(4) charset(1) reserved(23)
        end = payload.index(b"\x00", offset)
        username = payload[offset:end].decode("utf-8", "replace")
        cursor = end + 1
        if cursor < len(payload):
            auth_len = payload[cursor]
            return username, payload[cursor + 1:cursor + 1 + auth_len]
        return username, b""
    except (ValueError, IndexError):
        return "unknown", b""


async def main() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    print(f"[*] fake mysqld listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
