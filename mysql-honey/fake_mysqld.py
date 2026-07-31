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

from shared import alerting, identity, persona, tarpit  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "33306"))
SERVICE = "mysql"

# Must match what the web shell's fake MySQL console reports; both read the
# deployment's persona so the two halves tell the same story.
SERVER_VERSION = os.getenv("FAKE_MYSQL_VERSION") or persona.get("mysql_version")
MAX_SLEEP_SECONDS = float(os.getenv("MYSQL_MAX_SLEEP", "10"))
IDLE_TIMEOUT = int(os.getenv("MYSQL_IDLE_TIMEOUT", "300"))
TARPIT_MAX_SECONDS = int(os.getenv("MYSQL_TARPIT_MAX_SECONDS", "600"))
# A hostile client controls this length field, so it is a memory bound first
# and a persona detail second. Whatever it is set to, it is also what we tell
# clients when they ask for @@max_allowed_packet -- advertising a ceiling we
# will not honour just moves the disconnect from the handshake to the first
# large query. 1M is an ordinary value for a real server, so agreeing with
# ourselves here costs us nothing in plausibility.
MAX_PACKET = int(os.getenv("MYSQL_MAX_PACKET", str(1 << 20)))

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
SYSVAR_RE = re.compile(r"@@((?:session\.|global\.|local\.)?\w+)", re.I)
SHOW_VARS_RE = re.compile(r"show\s+(?:session\s+|global\s+|local\s+)?variables\b", re.I)
LIKE_RE = re.compile(r"\blike\s+'([^']*)'", re.I)


def like_to_regex(pattern: str) -> "re.Pattern":
    """Translate a SQL LIKE pattern into an anchored regex.

    Attacker-supplied, so it is built character by character with everything
    else escaped -- passing it to re.compile directly would let a probe hand
    us a catastrophically backtracking pattern.

    Backslash is LIKE's escape character, and clients rely on it: the probe
    for the charset family is `LIKE 'character\\_set\\_%'`, where an
    unescaped `_` would be a single-character wildcard.
    """
    parts = []
    escaped = False
    for char in pattern:
        if escaped:
            parts.append(re.escape(char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "%":
            parts.append(".*")
        elif char == "_":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    if escaped:  # trailing lone backslash is itself
        parts.append(re.escape("\\"))
    return re.compile("".join(parts) + r"\Z", re.I)

# What a client is told when it asks about the server it just connected to.
# These are not decoration: a connector reads @@max_allowed_packet to size its
# send buffer, @@sql_mode to decide how to quote, and @@lower_case_table_names
# to decide how to fold identifiers. Answer wrongly and it disconnects before
# the operator sees a single interesting query, so the values here are the
# stock ones from a default MySQL 8 install.
SYSVARS = {
    "max_allowed_packet": str(MAX_PACKET),
    "net_buffer_length": "16384",
    "net_write_timeout": "60",
    "net_read_timeout": "30",
    "wait_timeout": str(IDLE_TIMEOUT),
    "interactive_timeout": str(IDLE_TIMEOUT),
    "version": SERVER_VERSION,
    "version_comment": "(Ubuntu)",
    "version_compile_os": "Linux",
    "version_compile_machine": "x86_64",
    "protocol_version": "10",
    "sql_mode": ("ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,"
                 "NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"),
    "autocommit": "1",
    "lower_case_table_names": "0",
    "character_set_client": "utf8mb4",
    "character_set_connection": "utf8mb4",
    "character_set_results": "utf8mb4",
    "character_set_server": "utf8mb4",
    "character_set_database": "utf8mb4",
    "collation_server": "utf8mb4_0900_ai_ci",
    "collation_connection": "utf8mb4_0900_ai_ci",
    "collation_database": "utf8mb4_0900_ai_ci",
    "time_zone": "SYSTEM",
    "system_time_zone": "UTC",
    "transaction_isolation": "REPEATABLE-READ",
    "tx_isolation": "REPEATABLE-READ",
    "transaction_read_only": "0",
    "sql_select_limit": "18446744073709551615",
    "max_execution_time": "0",
    "have_query_cache": "NO",
    "query_cache_size": "0",
    "query_cache_type": "OFF",
    "license": "GPL",
    "hostname": "prod-db-01",
    "port": "3306",
    "datadir": "/var/lib/mysql/",
    "basedir": "/usr/",
    "secure_file_priv": "/var/lib/mysql-files/",
    "socket": "/var/run/mysqld/mysqld.sock",
    "auto_increment_increment": "1",
    "auto_increment_offset": "1",
    "init_connect": "",
    "performance_schema": "1",
    "server_id": "1",
    "read_only": "0",
    "super_read_only": "0",
    "foreign_key_checks": "1",
    "unique_checks": "1",
    "identity": "0",
    "last_insert_id": "0",
    "warning_count": "0",
    "error_count": "0",
    "session_track_gtids": "OFF",
    "session_track_schema": "1",
    "session_track_state_change": "0",
    "session_track_system_variables": "time_zone,autocommit,"
                                      "character_set_client,character_set_results,"
                                      "character_set_connection",
}

# An unrecognised variable is answered rather than refused. Real MySQL errors
# on an unknown one, but a scanner probing for exotic variables learns more
# from an error than it gives us, and an unexpected 0 is harmless to a client
# that only asked out of curiosity.
DEFAULT_SYSVAR = "0"


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
    return (lenenc_str("def") + lenenc_str(DB_NAME) + lenenc_str(table)
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

_DOMAIN = persona.get("company_domain")
# Same schema and login the web shell's fake MySQL console reports. These used
# to be hardcoded to "wordpress"/"wp_user" here and something else there, which
# is precisely the seam an attacker probing both looks for.
DB_NAME = persona.get("db_name")
DB_USER = persona.get("db_user")
# The staff account comes from the same pool the SSH honeypot uses, so a name
# harvested here belongs to a user that "exists" on the rest of the machine.
_STAFF = (persona.pool("user_pool") or [["jmarsh"]])[0][0]
_STAFF_DISPLAY = f"{_STAFF[0].upper()}. {_STAFF[1:].capitalize()}"

FAKE_USERS = [
    (1, "admin", "$P$BqZ7vK2nR8xLmYcD4wF6tG9hJ1sA0e/", f"admin@{_DOMAIN}",
     "Site Administrator"),
    (2, _STAFF, "$P$B4kL9mN2pQ7rS5tU8vW1xY3zA6bC0d.", f"{_STAFF}@{_DOMAIN}",
     _STAFF_DISPLAY),
    (3, "editor", "$P$BvX2cV5bN8mQ1wE4rT7yU0iO3pA6sD/", f"editor@{_DOMAIN}",
     "Content Editor"),
]


async def answer_query(ip: str, sql: str, state: dict = None) -> bytes:
    """Return the wire bytes for one COM_QUERY. Sequence always restarts at 1.

    `state`, when given, collects the verdicts the scoring calls below already
    return, so the connection loop can honour a tarpit or a ban the moment one
    is earned rather than on the attacker's next connection. Left out, this is
    a pure formatter -- which is what the tests use it as.
    """
    stripped = sql.strip().rstrip(";")
    low = stripped.lower()

    def score(event_type: str, payload: str = "", **kwargs):
        result = identity.score_named_event(ip, event_type, payload=payload,
                                            service=SERVICE, **kwargs)
        if state is not None:
            if result.get("banned"):
                state["banned"] = True
            if result.get("tarpitted"):
                state["tarpitted"] = True
        return result

    if OUTFILE_RE.search(low):
        score("SQLI_OOB", payload=stripped[:300])
        score("FILE_UPLOAD", payload=stripped[:300])
        identity.activate_tarpit(ip, "SQL INTO OUTFILE", SERVICE)
        return err_packet(1, 1290, "HY000",
                          "The MySQL server is running with the --secure-file-priv "
                          "option so it cannot execute this statement")

    if LOADFILE_RE.search(low):
        score("SQLI_OOB", payload=stripped[:300])
        identity.activate_tarpit(ip, "SQL LOAD_FILE/LOAD DATA", SERVICE)
        return err_packet(1, 1290, "HY000",
                          "The MySQL server is running with the --secure-file-priv "
                          "option so it cannot execute this statement")

    if XPCMD_RE.search(low):
        score("SQLI_OOB", payload=stripped[:300])
        return err_packet(1, 1305, "42000",
                          f"PROCEDURE {DB_NAME}.xp_cmdshell does not exist")

    match = SLEEP_RE.search(low)
    if match:
        score("SQLI_UNION_BLIND", payload=stripped[:300])
        identity.activate_tarpit(ip, "Time-based blind SQLi", SERVICE)
        # Honor the delay so timing oracles agree, but never unbounded.
        await asyncio.sleep(min(float(match.group(1)), MAX_SLEEP_SECONDS))
        return result_set(["SLEEP(%s)" % match.group(1)], [[0]], 1)

    if UNION_RE.search(low):
        score("SQLI_UNION_BLIND", payload=stripped[:300])
        identity.activate_tarpit(ip, "UNION SQLi", SERVICE)
        columns = max(1, low.count(",") + 1)
        return result_set([f"col{i + 1}" for i in range(columns)],
                          [[None] * columns], 1)

    if BLIND_RE.search(low) and "select" in low:
        score("SQLI_BASIC", payload=stripped[:300])
        identity.activate_tarpit(ip, "Boolean SQLi", SERVICE)

    if low.startswith("show databases"):
        return result_set(["Database"],
                          [["information_schema"], ["mysql"], ["performance_schema"],
                           ["sys"], [DB_NAME]], 1)

    if low.startswith("show tables"):
        return result_set([f"Tables_in_{DB_NAME}"], [[t] for t in FAKE_TABLES], 1)

    if low.startswith("show grants"):
        return result_set(
            [f"Grants for {DB_USER}@localhost"],
            [[f"GRANT ALL PRIVILEGES ON `{DB_NAME}`.* TO '{DB_USER}'@'localhost'"]], 1)

    if low.startswith("grant "):
        return ok_packet(1)

    # Answered from the same table as `SELECT @@...`, and honouring LIKE.
    # Older connectors probe with `SHOW VARIABLES LIKE 'max_allowed_packet'`
    # rather than SELECT, and ignoring the pattern handed them a list their
    # variable was not in -- the same disconnect, reached by a different route.
    if SHOW_VARS_RE.match(low):
        wanted = LIKE_RE.search(stripped)
        rows = sorted(SYSVARS.items())
        if wanted:
            pattern = like_to_regex(wanted.group(1))
            rows = [(name, value) for name, value in rows if pattern.match(name)]
        return result_set(["Variable_name", "Value"],
                          [[name, value] for name, value in rows], 1)

    if "information_schema.tables" in low:
        score("RECON_LS", payload=stripped[:300])
        return result_set(["table_schema", "table_name"],
                          [[DB_NAME, t] for t in FAKE_TABLES], 1)

    if "information_schema.schemata" in low:
        return result_set(["schema_name"],
                          [["information_schema"], ["mysql"], [DB_NAME]], 1)

    if "wp_users" in low:
        score("SQLI_BASIC", payload=stripped[:300])
        return result_set(
            ["ID", "user_login", "user_pass", "user_email", "display_name"],
            [list(row) for row in FAKE_USERS], 1, table="wp_users")

    # System variables, before the generic SELECT below.
    #
    # Every MySQL client asks for several of these during connection setup,
    # before it sends anything an operator would want to read, and it does not
    # merely display the answers -- it configures itself from them. Falling
    # through to the generic `SELECT` handler returned a column called `result`
    # containing "1", so a client asking for @@max_allowed_packet concluded it
    # could send one byte and hung up. Every session died at the handshake, and
    # the recordings all ended on the same line.
    #
    # The column name matters as much as the value: connectors look results up
    # by name, so it has to come back as `@@max_allowed_packet`.
    if low.startswith("select") and "@@" in low:
        names = SYSVAR_RE.findall(stripped)
        if names:
            columns, values = [], []
            for raw in names:
                bare = raw.split(".")[-1].lower()
                columns.append(f"@@{raw}")
                values.append(SYSVARS.get(bare, DEFAULT_SYSVAR))
            return result_set(columns, [values], 1)

    if low.startswith("select") and "version()" in low:
        return result_set(["version()"], [[SERVER_VERSION]], 1)

    if low.startswith("select") and ("user()" in low or "current_user" in low):
        return result_set(["user()"], [[f"{DB_USER}@localhost"]], 1)

    if low.startswith("select") and "database()" in low:
        return result_set(["database()"], [[DB_NAME]], 1)

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
    recorder = None

    # This service marked addresses for tarpitting and then answered them at
    # full speed anyway -- activate_tarpit() was called from five places in
    # answer_query() and nothing ever honoured the flag, so an IP tarpitted by
    # SSH or SMB got a fast MySQL. Now it drains like the rest of them, and
    # registers the hold so it shows up under "Held right now".
    state = {"tarpitted": identity.is_tarpitted(ip), "banned": False}
    hold_until = tarpit.deadline(TARPIT_MAX_SECONDS)
    held = 0.0
    hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS) \
        if state["tarpitted"] else None

    try:
        writer.write(handshake(os.getpid() & 0xFFFF))
        await writer.drain()

        response, _ = await asyncio.wait_for(read_packet(reader), timeout=30)
        username, auth_blob = parse_handshake_response(response)

        # The wire format is binary but the queries are text, so the recording
        # is written as the mysql(1) client transcript an operator would have
        # seen. The auth blob is a challenge-response hash, not a password --
        # recorded as-is because it is crackable evidence, not a credential.
        recorder = alerting.SessionRecorder(ip, SERVICE, title=f"mysql from {ip}")
        recorder.write_output(
            f"Server version: {SERVER_VERSION}\r\n"
            f"login: {username}  auth: {auth_blob.hex()[:32]}\r\n\r\n")

        identity.record_credential(ip, username, auth_blob.hex()[:64], SERVICE)
        verdict = identity.score_named_event(
            ip, "CREDENTIAL_ATTEMPT",
            payload=f"{username}:<auth {auth_blob.hex()[:32]}>", service=SERVICE,
        )
        state["tarpitted"] |= bool(verdict.get("tarpitted"))
        state["banned"] |= bool(verdict.get("banned"))
        if identity.detect_spray(ip):
            verdict = identity.score_named_event(ip, "CREDENTIAL_SPRAY",
                                                 service=SERVICE)
            state["banned"] |= bool(verdict.get("banned"))
            identity.activate_tarpit(ip, "MySQL credential spray", SERVICE)
            state["tarpitted"] = True

        # The login itself can be the thing that crosses a threshold, so honour
        # both verdicts before the connection is handed to the query loop.
        if state["tarpitted"] and hold_key is None:
            hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)
        if state["tarpitted"]:
            held += await tarpit.stall(hold_until)

        writer.write(ok_packet(2))
        await writer.drain()

        if state["banned"]:
            recorder.write_output("-- banned at login, closing\r\n")
            raise ConnectionResetError("banned at login")

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
            recorder.write_output(f"mysql> {sql}\r\n")
            alerting.alert_event(
                ip=ip, event_type="SQL_QUERY", service=SERVICE,
                reason="COM_QUERY received", payload=sql[:500],
            )
            was_tarpitted = state["tarpitted"]
            answer = await answer_query(ip, sql, state)
            # A query that earns the tarpit is held from that same reply on,
            # not from the next connection. begin_hold is idempotent per
            # connection because hold_key is only set once.
            if state["tarpitted"]:
                if not was_tarpitted:
                    recorder.write_output("-- tarpit engaged\r\n")
                if hold_key is None:
                    hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)
                held += await tarpit.stall(hold_until)
            writer.write(answer)
            await writer.drain()

            # Answer first, then drop: the query that crossed the threshold is
            # the one worth having a reply recorded against.
            if state["banned"]:
                recorder.write_output("-- banned mid-session, closing\r\n")
                break
    except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError,
            ConnectionResetError, struct.error):
        pass
    finally:
        tarpit.end_hold(hold_key)
        tarpit.log_hold(ip, SERVICE, held)
        # May not exist: a client that drops before the handshake response
        # never gets a recorder.
        if recorder is not None:
            if held:
                recorder.write_output(f"-- tarpit held this connection {held:.0f}s\r\n")
            recorder.close()
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
