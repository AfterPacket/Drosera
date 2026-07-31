#!/usr/bin/env python3
"""Fake SMB server on 445 (SMB2) and 139 (NetBIOS/SMB1).

Answers NEGOTIATE, issues an NTLM challenge on SESSION_SETUP, accepts every
TREE_CONNECT, and serves a fake directory tree so a client can open, list, read
and write. Captured NTLMv2 responses are reassembled into hashcat-format lines
as evidence -- nothing is ever verified or used to authenticate anywhere, no
path is resolved, and nothing an attacker writes reaches a disk.

Two things are deliberately not emulated, and both answer STATUS_NOT_SUPPORTED
rather than failing in a way a client cannot interpret:

  * DCERPC over \\srvsvc, which is how `smbclient -L` lists shares. Browsing a
    named share works; enumerating the server's share list does not.
  * Compound requests. Only the first command in a chain is answered, so a
    client that chains will wait for the rest until the idle timeout.
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

# SMB1 commands we answer. Everything else gets a clean error status.
#
# SMB1 is answered rather than refused because refusing it loses the single
# largest category of SMB traffic on the internet: MS17-010 scanners speak SMB1
# and nothing else. This used to reply to every SMB1 packet with an SMB2
# NEGOTIATE response, which such a client cannot parse -- it retried four times
# and hung up inside a second, every time.
SMB1_NEGOTIATE = 0x72
SMB1_SESSION_SETUP_ANDX = 0x73
SMB1_LOGOFF_ANDX = 0x74
SMB1_TREE_CONNECT_ANDX = 0x75
SMB1_TREE_DISCONNECT = 0x71
SMB1_ECHO = 0x2B
SMB1_NT_CREATE_ANDX = 0xA2
SMB1_TRANS2 = 0x32

SMB1_NAMES = {
    SMB1_NEGOTIATE: "NEGOTIATE",
    SMB1_SESSION_SETUP_ANDX: "SESSION_SETUP_ANDX",
    SMB1_LOGOFF_ANDX: "LOGOFF_ANDX",
    SMB1_TREE_CONNECT_ANDX: "TREE_CONNECT_ANDX",
    SMB1_TREE_DISCONNECT: "TREE_DISCONNECT",
    SMB1_ECHO: "ECHO",
    SMB1_NT_CREATE_ANDX: "NT_CREATE_ANDX",
    SMB1_TRANS2: "TRANSACTION2",
}

# Dialect strings that mean "I can speak SMB2, upgrade me". Only these justify
# answering an SMB1 packet with an SMB2 response; a client that offered neither
# is being handed a protocol it never claimed to understand.
SMB2_DIALECTS = ("SMB 2.???", "SMB 2.002")
# What we select when the client is SMB1-only. Index into its own dialect list,
# so it has to be looked up rather than assumed.
SMB1_PREFERRED = "NT LM 0.12"

# Non-extended security: the client then puts its LM and NTLM responses
# directly in SESSION_SETUP_ANDX, where they can be read without unpicking
# SPNEGO. Against a fixed challenge those are exactly as crackable as the
# NTLMv2 blobs captured on the SMB2 path, and this is the form the SMB1-only
# tools use anyway.
SMB1_FLAGS = 0x88                    # response, case-insensitive paths
SMB1_FLAGS2 = 0x4001                 # 32-bit NT status, long names
SMB1_CAPABILITIES = 0x000002D9       # raw mode, NT SMBs, status32, NT find

CMD_NEGOTIATE, CMD_SESSION_SETUP, CMD_LOGOFF = 0x0000, 0x0001, 0x0002
CMD_TREE_CONNECT, CMD_TREE_DISCONNECT, CMD_CREATE = 0x0003, 0x0004, 0x0005
CMD_CLOSE, CMD_FLUSH, CMD_READ, CMD_WRITE = 0x0006, 0x0007, 0x0008, 0x0009
CMD_LOCK, CMD_IOCTL, CMD_CANCEL, CMD_ECHO = 0x000A, 0x000B, 0x000C, 0x000D
CMD_QUERY_DIRECTORY, CMD_CHANGE_NOTIFY = 0x000E, 0x000F
CMD_QUERY_INFO, CMD_SET_INFO = 0x0010, 0x0011

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
    CMD_CLOSE: "CLOSE",
    CMD_FLUSH: "FLUSH",
    CMD_READ: "READ",
    CMD_WRITE: "WRITE",
    CMD_LOCK: "LOCK",
    CMD_IOCTL: "IOCTL",
    CMD_CANCEL: "CANCEL",
    CMD_ECHO: "ECHO",
    CMD_QUERY_DIRECTORY: "QUERY_DIRECTORY",
    CMD_CHANGE_NOTIFY: "CHANGE_NOTIFY",
    CMD_QUERY_INFO: "QUERY_INFO",
    CMD_SET_INFO: "SET_INFO",
}

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_NO_MORE_FILES = 0x80000006
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_END_OF_FILE = 0xC0000011
STATUS_INSUFFICIENT_RESOURCES = 0xC000009A

MAX_HANDLES = int(os.getenv("SMB_MAX_HANDLES", "512"))

SESSION_FLAG_IS_GUEST = 0x0001

FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020

# How many credential submissions are refused before the session is granted.
#
# Refusing every one of them -- which is what this did -- captures the first
# NTLMv2 response and then ends the conversation, because a client that cannot
# log in has nothing else to say. The hash is already captured by the time we
# decide, so refusing again buys one more spray attempt at the cost of every
# client that gives up after a single failure, and most give up. Granting a
# guest session instead is what turns a two-packet scan into a browse session
# we can record.
FAIL_ATTEMPTS = int(os.getenv("SMB_FAIL_ATTEMPTS", "0"))
ALLOW_SESSION = os.getenv("SMB_ALLOW_SESSION", "true").lower() != "false"

SERVER_GUID = os.urandom(16)
# Fixed so every captured NTLMv2 line is crackable against a known challenge.
SERVER_CHALLENGE = bytes.fromhex(os.getenv("SMB_NTLM_CHALLENGE", "1122334455667788"))
NTLM_TARGET = str(persona.get("company_slug")).upper()[:15] or "WORKGROUP"

SHARES = {"IPC$": 0x02, "C$": 0x01, "ADMIN$": 0x01, "SharedDocs": 0x01, "backups": 0x01}

_COMPANY = persona.get("company_name")

# What a client sees when it lists a share: (name, size, is_directory).
#
# These have to exist for the same reason the shares do. A client that connects
# to a share and finds nothing in it leaves, and an empty listing is also a
# strong tell -- a file server nobody uses is not a file server. Names are dull
# on purpose: the interesting thing is which one an attacker reaches for.
FAKE_TREE = {
    "SharedDocs": [
        ("Finance", 0, True),
        ("HR", 0, True),
        ("IT", 0, True),
        ("Handbook.pdf", 2_384_512, False),
        ("Office 365 Migration.docx", 148_992, False),
        ("passwords.xlsx", 24_576, False),
        ("Q3 Forecast.xlsx", 96_256, False),
    ],
    "backups": [
        ("sql", 0, True),
        ("veeam", 0, True),
        ("backup-config.xml", 8_192, False),
        ("prod-db-01-2026-07-24.bak", 4_294_967_296, False),
        ("prod-db-01-2026-07-25.bak", 4_301_258_752, False),
    ],
    "C$": [
        ("inetpub", 0, True),
        ("PerfLogs", 0, True),
        ("Program Files", 0, True),
        ("Users", 0, True),
        ("Windows", 0, True),
        ("pagefile.sys", 8_589_934_592, False),
    ],
    "ADMIN$": [
        ("System32", 0, True),
        ("Temp", 0, True),
        ("win.ini", 92, False),
    ],
}

# Served for READ on anything without its own body. Small and inert: the point
# is that a fetch succeeds and gets recorded, not that the contents reward it.
FILE_BODIES = {
    "win.ini": b"; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n",
    "backup-config.xml": (
        b'<?xml version="1.0" encoding="utf-8"?>\r\n<backup>\r\n'
        b"  <target>\\\\prod-nas-02\\backups</target>\r\n"
        b"  <retention days=\"30\" />\r\n  <schedule>0 2 * * *</schedule>\r\n"
        b"</backup>\r\n"),
}
DEFAULT_BODY = (
    f"This file is part of the {_COMPANY} file server.\r\n"
    "Contact the IT helpdesk if you believe you should not have access.\r\n"
).encode()

# Anything below the top level of a share. Mapping the whole tree would be a
# lot of invented detail for no gain -- what matters is that descending into a
# folder returns something rather than an error, so the client keeps going.
SUBDIR_CONTENTS = [
    ("2025", 0, True),
    ("2026", 0, True),
    ("notes.txt", 1_204, False),
    ("archive.zip", 18_446_744, False),
]


def path_leaf(name: str) -> str:
    return name.replace("/", "\\").rstrip("\\").split("\\")[-1]


def lookup_entry(share: str, name: str):
    """(size, is_dir) for a path inside a share, or None if it is not there."""
    leaf = path_leaf(name)
    if not leaf:
        return 0, True                    # the share root itself
    if share == "IPC$":
        return 0, False                   # a named pipe; opening one succeeds
    for entry, size, is_dir in FAKE_TREE.get(share, []) + SUBDIR_CONTENTS:
        if entry.lower() == leaf.lower():
            return size, is_dir
    return None


def listing_for(share: str, name: str):
    """What a directory contains, with the . and .. a real server sends."""
    if path_leaf(name):
        items = SUBDIR_CONTENTS
    else:
        items = FAKE_TREE.get(share, SUBDIR_CONTENTS)
    return [(".", 0, True), ("..", 0, True)] + list(items)


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
                           status: int = STATUS_MORE_PROCESSING,
                           flags: int = 0) -> bytes:
    # SessionFlags matters on a granted session: SMB2_SESSION_FLAG_IS_GUEST
    # tells the client this login is anonymous and so the session is not
    # signed. Leaving it clear after advertising signing makes a client that
    # asked for signing drop the connection, because we cannot sign anything.
    body = (struct.pack("<H", 9) + struct.pack("<H", flags)
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


# ------------------------------------------------------------------ SMB1

def smb1_header(command: int, status: int = STATUS_SUCCESS, tree_id: int = 0,
                uid: int = 0, pid: int = 0, mid: int = 0) -> bytes:
    """The fixed 32-byte SMB1 header."""
    return (
        SMB1_MAGIC
        + bytes([command])
        + struct.pack("<I", status)
        + bytes([SMB1_FLAGS])
        + struct.pack("<H", SMB1_FLAGS2)
        + struct.pack("<H", 0)          # PIDHigh
        + b"\x00" * 8                   # SecurityFeatures
        + struct.pack("<H", 0)          # Reserved
        + struct.pack("<H", tree_id)
        + struct.pack("<H", pid)
        + struct.pack("<H", uid)
        + struct.pack("<H", mid)
    )


def smb1_fields(payload: bytes):
    """(command, tree_id, pid, uid, mid, parameters, data) from a request.

    Returns empty parameters/data rather than raising on a short packet: this
    is attacker input, and a malformed header should produce an error reply,
    not end the connection.
    """
    command = payload[4]
    tree_id, pid, uid, mid = struct.unpack("<HHHH", payload[24:32])
    parameters, data = b"", b""
    if len(payload) > 32:
        word_count = payload[32]
        start = 33 + word_count * 2
        parameters = payload[33:start]
        if len(payload) >= start + 2:
            byte_count, = struct.unpack("<H", payload[start:start + 2])
            data = payload[start + 2:start + 2 + byte_count]
    return command, tree_id, pid, uid, mid, parameters, data


def smb1_dialects(data: bytes):
    """Dialect strings offered in a NEGOTIATE request.

    The buffer is a series of 0x02-prefixed, NUL-terminated ASCII strings.
    """
    offered = []
    for chunk in data.split(b"\x02"):
        name = chunk.split(b"\x00", 1)[0]
        if name:
            offered.append(name.decode("ascii", "replace"))
    return offered


def smb1_message(command: int, words: bytes, data: bytes, status: int = STATUS_SUCCESS,
                 tree_id: int = 0, uid: int = 0, pid: int = 0, mid: int = 0) -> bytes:
    """Assemble a reply. WordCount is in words; ByteCount is in bytes."""
    return (smb1_header(command, status, tree_id, uid, pid, mid)
            + bytes([len(words) // 2]) + words
            + struct.pack("<H", len(data)) + data)


def smb1_error(command: int, status: int, tree_id: int = 0, uid: int = 0,
               pid: int = 0, mid: int = 0) -> bytes:
    return smb1_message(command, b"", b"", status, tree_id, uid, pid, mid)


def smb1_negotiate_response(index: int, pid: int, mid: int) -> bytes:
    """NEGOTIATE response selecting the dialect at `index` in the client's list."""
    domain = NTLM_TARGET.encode("ascii", "replace") + b"\x00"
    words = (
        struct.pack("<H", index)
        + bytes([0x03])                      # user-level security, encrypted passwords
        + struct.pack("<H", 50)              # MaxMpxCount
        + struct.pack("<H", 1)               # MaxNumberVcs
        + struct.pack("<I", 16644)           # MaxBufferSize
        + struct.pack("<I", 65536)           # MaxRawSize
        + struct.pack("<I", 0)               # SessionKey
        + struct.pack("<I", SMB1_CAPABILITIES)
        + struct.pack("<Q", filetime(time.time()))
        + struct.pack("<h", 0)               # ServerTimeZone
        + bytes([len(SERVER_CHALLENGE)])     # ChallengeLength
    )
    return smb1_message(SMB1_NEGOTIATE, words, SERVER_CHALLENGE + domain,
                        pid=pid, mid=mid)


def smb1_session_setup_response(uid: int, pid: int, mid: int, guest: bool) -> bytes:
    """SESSION_SETUP_ANDX response. Action bit 0 marks the logon as guest."""
    words = (b"\xff"                         # AndXCommand: none
             + b"\x00"                       # AndXReserved
             + struct.pack("<H", 0)          # AndXOffset
             + struct.pack("<H", 1 if guest else 0))
    data = b"Unix\x00Samba\x00" + NTLM_TARGET.encode("ascii", "replace") + b"\x00"
    return smb1_message(SMB1_SESSION_SETUP_ANDX, words, data,
                        uid=uid, pid=pid, mid=mid)


def smb1_tree_connect_response(tree_id: int, uid: int, pid: int, mid: int,
                               service: str) -> bytes:
    words = (b"\xff" + b"\x00" + struct.pack("<H", 0)
             + struct.pack("<H", 0x0001))    # OptionalSupport: search bits
    data = service.encode("ascii") + b"\x00" + b"NTFS\x00"
    return smb1_message(SMB1_TREE_CONNECT_ANDX, words, data,
                        tree_id=tree_id, uid=uid, pid=pid, mid=mid)


def smb1_credentials(parameters: bytes, data: bytes):
    """(account, domain, lm_response, nt_response) from SESSION_SETUP_ANDX.

    Non-extended security puts both password responses in the byte field ahead
    of the account name, with their lengths in the parameter words.
    """
    if len(parameters) < 26:
        return "", "", b"", b""
    lm_length, nt_length = struct.unpack("<HH", parameters[14:18])
    lm_response = data[:lm_length]
    nt_response = data[lm_length:lm_length + nt_length]
    rest = data[lm_length + nt_length:].split(b"\x00")
    account = rest[0].decode("utf-8", "replace") if rest else ""
    domain = rest[1].decode("utf-8", "replace") if len(rest) > 1 else ""
    return account, domain, lm_response, nt_response


# ------------------------------------------------------- file operations
#
# Everything below exists because a client that gets STATUS_NOT_IMPLEMENTED
# hangs up. NEGOTIATE, SESSION_SETUP and TREE_CONNECT were answered, and then
# the very next thing every client sends -- CREATE, to open something on the
# share it just connected to -- fell through to the catch-all error. From the
# attacker's side the server accepted the share and then broke, so sessions
# ended one command after they started and the transcripts all looked the same.
#
# These are the minimum needed for a client to open, list, read and write, and
# they are pure formatting: no path is resolved and nothing touches a disk.

def file_times(age_days: float = 40.0) -> bytes:
    """Created, accessed, written, changed -- four FILETIMEs, in wire order."""
    now = time.time()
    written = filetime(now - age_days * 86400)
    return struct.pack("<QQQQ", filetime(now - (age_days + 300) * 86400),
                       filetime(now - 3600), written, written)


def allocation_of(size: int) -> int:
    """Round to a cluster, the way a real filesystem reports it."""
    return (size + 4095) // 4096 * 4096


def create_response(message_id: int, session_id: int, tree_id: int,
                    file_id: bytes, size: int, is_dir: bool) -> bytes:
    attributes = FILE_ATTRIBUTE_DIRECTORY if is_dir else FILE_ATTRIBUTE_ARCHIVE
    body = (
        struct.pack("<H", 89)
        + b"\x00"                          # OplockLevel: none
        + b"\x00"                          # Flags
        + struct.pack("<I", 1)             # CreateAction: FILE_OPENED
        + file_times()
        + struct.pack("<Q", allocation_of(size))
        + struct.pack("<Q", size)
        + struct.pack("<I", attributes)
        + struct.pack("<I", 0)             # Reserved2
        + file_id
        + struct.pack("<I", 0)             # CreateContextsOffset
        + struct.pack("<I", 0)             # CreateContextsLength
    )
    return smb2_header(CMD_CREATE, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def close_response(message_id: int, session_id: int, tree_id: int) -> bytes:
    body = (struct.pack("<H", 60) + struct.pack("<H", 0) + struct.pack("<I", 0)
            + file_times() + struct.pack("<Q", 0) + struct.pack("<Q", 0)
            + struct.pack("<I", 0))
    return smb2_header(CMD_CLOSE, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def read_response(message_id: int, session_id: int, tree_id: int,
                  data: bytes) -> bytes:
    body = (struct.pack("<H", 17) + bytes([64 + 16]) + b"\x00"
            + struct.pack("<I", len(data)) + struct.pack("<I", 0)
            + struct.pack("<I", 0) + data)
    return smb2_header(CMD_READ, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def write_response(message_id: int, session_id: int, tree_id: int,
                   count: int) -> bytes:
    body = (struct.pack("<H", 17) + struct.pack("<H", 0)
            + struct.pack("<I", count) + struct.pack("<I", 0)
            + struct.pack("<H", 0) + struct.pack("<H", 0))
    return smb2_header(CMD_WRITE, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def directory_entries(items) -> bytes:
    """FileBothDirectoryInformation records, chained and 8-byte aligned.

    NextEntryOffset is the distance to the next record and zero on the last
    one; a client walks the chain by it, so an entry whose padding is not
    counted sends the client into the middle of the following record.
    """
    chunks = []
    for name, size, is_dir in items:
        encoded = name.encode("utf-16le")
        attributes = FILE_ATTRIBUTE_DIRECTORY if is_dir else FILE_ATTRIBUTE_ARCHIVE
        entry = (
            struct.pack("<I", 0)               # NextEntryOffset, filled in below
            + struct.pack("<I", 0)             # FileIndex
            + file_times()
            + struct.pack("<Q", size)
            + struct.pack("<Q", allocation_of(size))
            + struct.pack("<I", attributes)
            + struct.pack("<I", len(encoded))
            + struct.pack("<I", 0)             # EaSize
            + b"\x00"                          # ShortNameLength
            + b"\x00"                          # Reserved
            + b"\x00" * 24                     # ShortName
            + encoded
        )
        chunks.append(entry + b"\x00" * (-len(entry) % 8))

    out = b""
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        out += struct.pack("<I", 0 if last else len(chunk)) + chunk[4:]
    return out


def buffered_response(command: int, message_id: int, session_id: int,
                      tree_id: int, buffer: bytes) -> bytes:
    """QUERY_DIRECTORY and QUERY_INFO share this reply shape."""
    body = (struct.pack("<H", 9) + struct.pack("<H", 64 + 8)
            + struct.pack("<I", len(buffer)) + buffer)
    return smb2_header(command, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def simple_response(command: int, message_id: int, session_id: int,
                    tree_id: int, structure_size: int) -> bytes:
    body = struct.pack("<H", structure_size) + b"\x00" * (structure_size - 2)
    return smb2_header(command, message_id, tree_id=tree_id,
                       session_id=session_id) + body


def file_info(info_class: int, size: int, is_dir: bool):
    """MS-FSCC file information, or None for a class we do not serve."""
    attributes = FILE_ATTRIBUTE_DIRECTORY if is_dir else FILE_ATTRIBUTE_ARCHIVE
    if info_class == 0x04:                      # FileBasicInformation
        return file_times() + struct.pack("<II", attributes, 0)
    if info_class == 0x05:                      # FileStandardInformation
        return (struct.pack("<Q", allocation_of(size)) + struct.pack("<Q", size)
                + struct.pack("<I", 1) + bytes([0, 1 if is_dir else 0])
                + struct.pack("<H", 0))
    if info_class == 0x22:                      # FileNetworkOpenInformation
        return (file_times() + struct.pack("<Q", allocation_of(size))
                + struct.pack("<Q", size) + struct.pack("<II", attributes, 0))
    return None


def filesystem_info(info_class: int):
    """MS-FSCC filesystem information -- what `ls` prints as free space."""
    if info_class == 0x01:                      # FileFsVolumeInformation
        label = "Data".encode("utf-16le")
        return (struct.pack("<Q", filetime(time.time() - 700 * 86400))
                + struct.pack("<I", 0x9C2F41B7) + struct.pack("<I", len(label))
                + b"\x00\x00" + label)
    if info_class == 0x03:                      # FileFsSizeInformation
        return (struct.pack("<Q", 244_190_625) + struct.pack("<Q", 91_234_112)
                + struct.pack("<I", 8) + struct.pack("<I", 512))
    if info_class == 0x05:                      # FileFsAttributeInformation
        name = "NTFS".encode("utf-16le")
        return (struct.pack("<I", 0x000700FF) + struct.pack("<I", 255)
                + struct.pack("<I", len(name)) + name)
    if info_class == 0x07:                      # FileFsFullSizeInformation
        return (struct.pack("<Q", 244_190_625) + struct.pack("<Q", 91_234_112)
                + struct.pack("<Q", 91_234_112) + struct.pack("<I", 8)
                + struct.pack("<I", 512))
    return None


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
    handles = {}          # file id -> (share, name, size, is_dir, listed)
    auth_attempts = 0
    smb1_uid = 0          # allocated on the SMB1 path only

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
    # Set when an event crosses the ban threshold part-way through. The ban is
    # only checked at connect, so without this an address that earns one mid
    # session keeps the connection it is already holding and is refused on its
    # next one -- which, on a long share enumeration, may be a while.
    banned = False

    def engage():
        """Start holding this connection, mid-session if need be.

        Sampling is_tarpitted() once at connect leaves a gap: an address that
        crosses the threshold part-way through a share enumeration -- or that is
        pushed over it by a *different* service scoring it at the same moment,
        since the score is shared -- would keep getting fast answers until it
        reconnected. Share enumeration is exactly where that matters, because it
        is one long connection rather than many short ones.
        """
        nonlocal tarpitted, hold_key
        if tarpitted:
            return
        tarpitted = True
        identity.score_named_event(ip, "TARPIT_ENGAGED", payload="smb tarpit",
                                   service=SERVICE)
        hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)
        recorder.write_output("tarpit engaged\r\n")

    def score(event_type: str, payload: str = ""):
        """Score, then honour the verdict immediately.

        score_named_event already returns whether the address is tarpitted or
        banned as of this event -- including when another service pushed it
        over a threshold a moment ago -- so acting on either costs no extra
        Redis call.
        """
        nonlocal banned
        result = identity.score_named_event(ip, event_type, payload=payload,
                                            service=SERVICE)
        if result.get("tarpitted"):
            engage()
        if result.get("banned"):
            banned = True
        return result

    if tarpitted:
        tarpitted = False       # let engage() do the work uniformly
        engage()

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

            if payload.startswith(SMB1_MAGIC) and len(payload) >= 32:
                cmd1, tid1, pid1, uid1, mid1, params1, data1 = smb1_fields(payload)
                recorder.write_output(
                    f"SMB1 {SMB1_NAMES.get(cmd1, f'0x{cmd1:02x}')}\r\n")

                if cmd1 == SMB1_NEGOTIATE:
                    offered = smb1_dialects(data1)
                    recorder.write_output(f"  dialects: {', '.join(offered)}\r\n")
                    score("SMB_ENUM", f"SMB1 negotiate: {','.join(offered)}"[:200])
                    upgrade = next((name for name in offered
                                    if name in SMB2_DIALECTS), None)
                    if upgrade:
                        # It asked for SMB2 by name, so the SMB2 reply is an
                        # answer rather than a non-sequitur.
                        recorder.write_output(f"  -> upgrading via {upgrade}\r\n")
                        writer.write(wrap_nbt(negotiate_response(0)))
                    elif SMB1_PREFERRED in offered:
                        smb1_uid = smb1_uid or int.from_bytes(os.urandom(2), "little") or 1
                        writer.write(wrap_nbt(smb1_negotiate_response(
                            offered.index(SMB1_PREFERRED), pid1, mid1)))
                    else:
                        # 0xFFFF means "none of your dialects", which is a real
                        # answer -- the client stops rather than retrying.
                        writer.write(wrap_nbt(smb1_negotiate_response(
                            0xFFFF, pid1, mid1)))

                elif cmd1 == SMB1_SESSION_SETUP_ANDX:
                    account, domain, lm_response, nt_response = smb1_credentials(
                        params1, data1)
                    if nt_response or lm_response:
                        blob = (nt_response or lm_response).hex()
                        recorder.write_output(
                            f"  {domain}\\{account} response {blob[:48]}\r\n")
                        identity.record_credential(
                            ip, f"{domain}\\{account}" if domain else account,
                            blob[:128], SERVICE)
                        score("CREDENTIAL_ATTEMPT", f"SMB1 {account}"[:200])
                    smb1_uid = smb1_uid or int.from_bytes(os.urandom(2), "little") or 1
                    auth_attempts += 1
                    # The stall at the end of this block covers the reply; a
                    # second one here would drain the same response twice.
                    if identity.is_tarpitted(ip):
                        engage()
                    if ALLOW_SESSION and auth_attempts > FAIL_ATTEMPTS:
                        writer.write(wrap_nbt(smb1_session_setup_response(
                            smb1_uid, pid1, mid1, guest=True)))
                    else:
                        writer.write(wrap_nbt(smb1_error(
                            SMB1_SESSION_SETUP_ANDX, STATUS_LOGON_FAILURE,
                            pid=pid1, mid=mid1)))

                elif cmd1 == SMB1_TREE_CONNECT_ANDX:
                    share = data1.split(b"\x00")[0].decode("utf-8", "replace")
                    leaf = share.rstrip("\\").split("\\")[-1] or "IPC$"
                    recorder.write_output(f"  share {share or leaf}\r\n")
                    score("SMB_ENUM", f"SMB1 TREE_CONNECT {share}"[:200])
                    tree_counter += 1
                    trees[tree_counter] = leaf
                    writer.write(wrap_nbt(smb1_tree_connect_response(
                        tree_counter, uid1, pid1, mid1,
                        "IPC" if leaf == "IPC$" else "A:")))

                elif cmd1 in (SMB1_ECHO, SMB1_TREE_DISCONNECT, SMB1_LOGOFF_ANDX):
                    writer.write(wrap_nbt(smb1_message(
                        cmd1, b"", b"", tree_id=tid1, uid=uid1, pid=pid1, mid=mid1)))

                else:
                    # NT_CREATE_ANDX and TRANS2 land here. An MS17-010 probe
                    # expects a status back from its TRANS2, and a refusal is
                    # what an unaffected host returns -- the point is that it
                    # is a refusal it can parse, not silence.
                    score("SMB_ENUM", f"SMB1 command 0x{cmd1:02x}")
                    writer.write(wrap_nbt(smb1_error(
                        cmd1, STATUS_NOT_IMPLEMENTED, tree_id=tid1, uid=uid1,
                        pid=pid1, mid=mid1)))

                if tarpitted:
                    held += await tarpit.stall(hold_until)
                await writer.drain()
                if banned:
                    recorder.write_output("banned mid-session -- closing\r\n")
                    break
                continue

            if not payload.startswith(SMB2_MAGIC) or len(payload) < 64:
                break

            command, = struct.unpack("<H", payload[12:14])
            message_id, = struct.unpack("<Q", payload[24:32])
            tree_id, = struct.unpack("<I", payload[36:40])
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
                score("SMB_ENUM", "SMB2 NEGOTIATE")
                writer.write(wrap_nbt(negotiate_response(message_id)))

            elif command == CMD_SESSION_SETUP:
                blob = body[24:] if len(body) > 24 else b""
                if b"NTLMSSP\x00" in blob and len(blob) > 20:
                    index = blob.find(b"NTLMSSP\x00")
                    msg = struct.unpack("<I", blob[index + 8:index + 12])[0] \
                        if len(blob) >= index + 12 else 1
                    if msg == 3:
                        auth_attempts += 1
                        parse_ntlm_auth(blob, ip)
                        # parse_ntlm_auth scores internally, so its verdict is
                        # not in a return value here. Auth attempts are rare
                        # next to PDUs, and this is the branch a password spray
                        # sits in, so one lookup is worth it.
                        if identity.is_tarpitted(ip):
                            engage()
                        # Slow the answer either way: this is the branch a
                        # password spray hits over and over, so it is the one
                        # where a delay costs the attacker the most.
                        if tarpitted:
                            held += await tarpit.stall(hold_until)
                        # The hash is captured by now, so refusing again buys
                        # nothing except an ended session. Grant it as a guest
                        # and let them go looking around, which is the part
                        # worth recording.
                        if ALLOW_SESSION and auth_attempts > FAIL_ATTEMPTS:
                            recorder.write_output(
                                "  NTLMSSP_AUTH -> STATUS_SUCCESS (guest)\r\n")
                            writer.write(wrap_nbt(session_setup_response(
                                message_id, session_id, b"", STATUS_SUCCESS,
                                SESSION_FLAG_IS_GUEST)))
                        else:
                            recorder.write_output(
                                "  NTLMSSP_AUTH -> STATUS_LOGON_FAILURE\r\n")
                            writer.write(wrap_nbt(error_response(
                                CMD_SESSION_SETUP, message_id,
                                STATUS_LOGON_FAILURE, session_id)))
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
                score("SMB_ENUM", f"TREE_CONNECT {share}"[:200])
                tree_counter += 1
                trees[tree_counter] = leaf
                writer.write(wrap_nbt(tree_connect_response(
                    message_id, session_id, tree_counter,
                    SHARES.get(leaf, 0x01))))

            elif command == CMD_CREATE:
                name = ""
                disposition, options = 1, 0
                try:
                    disposition, options = struct.unpack("<II", body[36:44])
                    offset, length = struct.unpack("<HH", body[44:48])
                    name = payload[offset:offset + length].decode(
                        "utf-16le", "replace")
                except (struct.error, IndexError):
                    pass
                share = trees.get(tree_id, "IPC$")
                found = lookup_entry(share, name)
                # FILE_OPEN only opens what exists; every other disposition is
                # allowed to create. An attacker dropping a payload on an open
                # share arrives here, and refusing would lose the upload we
                # most want to see -- so a create succeeds and the bytes get
                # captured at WRITE.
                creating = disposition != 1 and found is None
                if found is None and not creating:
                    recorder.write_output(
                        f"  CREATE {share}\\{name} -> not found\r\n")
                    # Stall before answering, like every other reply in this
                    # loop. Returning early past the stall at the bottom would
                    # make a miss the one fast response a tarpitted client can
                    # get, and guessing filenames is cheap to do in bulk.
                    if tarpitted:
                        held += await tarpit.stall(hold_until)
                    writer.write(wrap_nbt(error_response(
                        CMD_CREATE, message_id, STATUS_OBJECT_NAME_NOT_FOUND,
                        session_id)))
                    await writer.drain()
                    continue
                # Opens are attacker-driven and closes are optional, so this
                # dictionary only ever grows unless something stops it. A real
                # server has a handle limit too, and hits it the same way.
                if len(handles) >= MAX_HANDLES:
                    if tarpitted:
                        held += await tarpit.stall(hold_until)
                    writer.write(wrap_nbt(error_response(
                        CMD_CREATE, message_id, STATUS_INSUFFICIENT_RESOURCES,
                        session_id)))
                    await writer.drain()
                    continue
                size, is_dir = found if found else (0, bool(options & 0x01))
                file_id = os.urandom(16)
                handles[file_id] = [share, name, size, is_dir, False]
                recorder.write_output(
                    f"  {'CREATE' if creating else 'OPEN'} "
                    f"{share}\\{name or '.'}\r\n")
                score("SMB_ENUM", f"CREATE {share}\\{name}"[:200])
                writer.write(wrap_nbt(create_response(
                    message_id, session_id, tree_id, file_id, size, is_dir)))

            elif command == CMD_CLOSE:
                handles.pop(body[8:24], None)
                writer.write(wrap_nbt(close_response(
                    message_id, session_id, tree_id)))

            elif command == CMD_QUERY_DIRECTORY:
                file_id = body[8:24]
                entry = handles.get(file_id)
                # A client asks twice: once for the entries and once more to be
                # told there are no others. Answering with the same list both
                # times leaves it enumerating the same directory forever, so
                # the second call has to be STATUS_NO_MORE_FILES.
                restart = bool(body[3] & 0x11) if len(body) > 3 else False
                if entry and (restart or not entry[4]):
                    entry[4] = True
                    share, name = entry[0], entry[1]
                    recorder.write_output(f"  LIST {share}\\{name or '.'}\r\n")
                    score("SMB_ENUM", f"QUERY_DIRECTORY {share}\\{name}"[:200])
                    writer.write(wrap_nbt(buffered_response(
                        CMD_QUERY_DIRECTORY, message_id, session_id, tree_id,
                        directory_entries(listing_for(share, name)))))
                else:
                    writer.write(wrap_nbt(error_response(
                        CMD_QUERY_DIRECTORY, message_id, STATUS_NO_MORE_FILES,
                        session_id)))

            elif command == CMD_QUERY_INFO:
                info_type = body[2] if len(body) > 2 else 1
                info_class = body[3] if len(body) > 3 else 0
                entry = handles.get(body[24:40])
                if info_type == 0x02:
                    buffer = filesystem_info(info_class)
                else:
                    size, is_dir = (entry[2], entry[3]) if entry else (0, True)
                    buffer = file_info(info_class, size, is_dir)
                if buffer is None:
                    writer.write(wrap_nbt(error_response(
                        CMD_QUERY_INFO, message_id, STATUS_NOT_SUPPORTED,
                        session_id)))
                else:
                    writer.write(wrap_nbt(buffered_response(
                        CMD_QUERY_INFO, message_id, session_id, tree_id, buffer)))

            elif command == CMD_READ:
                length, = struct.unpack("<I", body[4:8])
                offset, = struct.unpack("<Q", body[8:16])
                entry = handles.get(body[16:32])
                name = entry[1] if entry else ""
                content = FILE_BODIES.get(path_leaf(name), DEFAULT_BODY)
                chunk = content[offset:offset + min(length, MAX_PDU)]
                if not chunk:
                    writer.write(wrap_nbt(error_response(
                        CMD_READ, message_id, STATUS_END_OF_FILE, session_id)))
                else:
                    recorder.write_output(
                        f"  READ {name or '?'} ({len(chunk)} bytes)\r\n")
                    score("FILE_DOWNLOAD", f"SMB read {name}"[:200])
                    writer.write(wrap_nbt(read_response(
                        message_id, session_id, tree_id, chunk)))

            elif command == CMD_WRITE:
                data_offset, = struct.unpack("<H", body[2:4])
                length, = struct.unpack("<I", body[4:8])
                entry = handles.get(body[16:32])
                name = entry[1] if entry else ""
                data = payload[data_offset:data_offset + length]
                # Nothing is written anywhere. The bytes go into the transcript
                # as evidence and are then dropped -- an upload to an open
                # share is one of the more useful things to catch, and the file
                # it would have become is one of the more dangerous to keep.
                #
                # Acknowledge what arrived, not what the header claimed: Length
                # is attacker-controlled and can name far more than the PDU
                # carried, and a client told it wrote four gigabytes puts the
                # next write at an offset neither side agrees on.
                recorder.write_output(
                    f"  WRITE {name or '?'} ({len(data)} bytes)\r\n"
                    f"    {binascii.hexlify(data[:64]).decode()}\r\n")
                score("FILE_UPLOAD", f"SMB write {name} ({len(data)} bytes)"[:200])
                writer.write(wrap_nbt(write_response(
                    message_id, session_id, tree_id, len(data))))

            elif command == CMD_SET_INFO:
                writer.write(wrap_nbt(simple_response(
                    CMD_SET_INFO, message_id, session_id, tree_id, 2)))

            elif command in (CMD_ECHO, CMD_FLUSH, CMD_LOCK):
                writer.write(wrap_nbt(simple_response(
                    command, message_id, session_id, tree_id, 4)))

            elif command == CMD_CANCEL:
                # Cancel is the one request with no reply. Sending anything
                # here puts an extra response in the stream that the client
                # will match against its next request.
                continue

            elif command == CMD_IOCTL:
                # Share enumeration proper runs DCERPC over the \srvsvc pipe,
                # which is a whole protocol above this one and is not emulated.
                # NOT_SUPPORTED is a refusal the client understands and moves
                # on from; the unhandled-command error it used to get was not.
                score("SMB_ENUM", "IOCTL")
                writer.write(wrap_nbt(error_response(
                    CMD_IOCTL, message_id, STATUS_NOT_SUPPORTED, session_id)))

            elif command == CMD_CHANGE_NOTIFY:
                writer.write(wrap_nbt(error_response(
                    CMD_CHANGE_NOTIFY, message_id, STATUS_NOT_SUPPORTED,
                    session_id)))

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
                # Only OPLOCK_BREAK and future commands reach this now. It used
                # to catch CREATE and everything after it, which is why sessions
                # ended one command past TREE_CONNECT.
                writer.write(wrap_nbt(error_response(
                    command, message_id, STATUS_NOT_IMPLEMENTED, session_id)))

            if tarpitted:
                held += await tarpit.stall(hold_until)
            await writer.drain()

            # Answer the request that crossed the line before dropping them:
            # it is already scored and recorded, and cutting the reply would
            # lose the response an analyst reads alongside it.
            if banned:
                recorder.write_output("banned mid-session -- closing\r\n")
                break
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
