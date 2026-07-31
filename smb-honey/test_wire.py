#!/usr/bin/env python3
"""Check the SMB2 response structures a browsing client depends on.

Every one of these has a fixed size and a self-declared StructureSize, and a
client validates both before it will read the response. Getting either wrong
looks exactly like the bug this file was written for: the server answers, the
client hangs up, and the transcript ends mid-session with no error anywhere.

Offsets here are the ones from MS-SMB2 and MS-FSCC, written out rather than
computed, so a change to a builder has to disagree with the spec to pass.
"""

import os
import pathlib
import struct
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "smb-honey"))
os.environ.setdefault("REDIS_HOST", "127.0.0.1")
# Never the real storage: a test run should not land in the evidence log next
# to actual attacker traffic.
os.environ.setdefault("STORAGE_PATH", tempfile.mkdtemp(prefix="drosera-test-"))


def stub_redis_if_missing() -> None:
    """Let this run on a host that has no redis-py.

    Nothing here exercises Redis -- these are wire-format checks -- but
    importing the service pulls in shared.identity, which imports redis at
    module scope. The package is installed inside the containers, so on the
    host the import fails before a single check runs.

    identity._client() catches any exception from the constructor and falls
    back to its degraded path, so a stub that refuses to connect is
    indistinguishable from Redis being down, which the appliance already
    handles.
    """
    try:
        import redis  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    class Unavailable(Exception):
        pass

    class Redis:
        def __init__(self, *args, **kwargs):
            raise Unavailable("redis-py not installed; stubbed for tests")

    module = types.ModuleType("redis")
    module.Redis = Redis
    module.RedisError = Unavailable
    module.ConnectionError = Unavailable
    module.TimeoutError = Unavailable
    module.exceptions = types.SimpleNamespace(
        RedisError=Unavailable, ConnectionError=Unavailable,
        TimeoutError=Unavailable)
    sys.modules["redis"] = module


stub_redis_if_missing()

import fake_smbd as s  # noqa: E402

HEADER = 64


def body_of(response):
    """Strip the SMB2 header, checking it is one first."""
    assert response[:4] == s.SMB2_MAGIC, "not an SMB2 response"
    assert struct.unpack("<H", response[4:6])[0] == 64, "bad header size"
    return response[HEADER:]


def status_of(response):
    return struct.unpack("<I", response[8:12])[0]


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return 0 if condition else 1


def main():
    bad = 0

    # --- CREATE: 88 fixed bytes, declared as 89 --------------------------
    file_id = bytes(range(16))
    body = body_of(s.create_response(1, 2, 3, file_id, 4096, False))
    bad += check("CREATE fixed part is 88 bytes", len(body) == 88, len(body))
    bad += check("CREATE declares StructureSize 89",
                 struct.unpack("<H", body[0:2])[0] == 89)
    bad += check("CREATE echoes the file id back", body[64:80] == file_id)
    bad += check("CREATE reports the size at EndOfFile",
                 struct.unpack("<Q", body[48:56])[0] == 4096)
    body = body_of(s.create_response(1, 2, 3, file_id, 0, True))
    bad += check("CREATE marks a directory",
                 struct.unpack("<I", body[56:60])[0] & s.FILE_ATTRIBUTE_DIRECTORY)

    # --- CLOSE: 60 bytes, declared 60 ------------------------------------
    body = body_of(s.close_response(1, 2, 3))
    bad += check("CLOSE is 60 bytes", len(body) == 60, len(body))
    bad += check("CLOSE declares StructureSize 60",
                 struct.unpack("<H", body[0:2])[0] == 60)

    # --- READ: DataOffset is measured from the header ---------------------
    payload = b"hello world"
    body = body_of(s.read_response(1, 2, 3, payload))
    bad += check("READ declares StructureSize 17",
                 struct.unpack("<H", body[0:2])[0] == 17)
    offset = body[2]
    bad += check("READ DataOffset points past its own fixed part",
                 offset == HEADER + 16, offset)
    bad += check("READ DataLength matches the data",
                 struct.unpack("<I", body[4:8])[0] == len(payload))
    whole = s.read_response(1, 2, 3, payload)
    bad += check("READ data sits where DataOffset says",
                 whole[offset:offset + len(payload)] == payload)

    # --- WRITE ------------------------------------------------------------
    body = body_of(s.write_response(1, 2, 3, 4321))
    bad += check("WRITE is 16 bytes declared as 17",
                 len(body) == 16 and struct.unpack("<H", body[0:2])[0] == 17,
                 len(body))
    bad += check("WRITE acknowledges the byte count",
                 struct.unpack("<I", body[4:8])[0] == 4321)

    # --- QUERY_DIRECTORY: the chain a client walks ------------------------
    items = s.listing_for("SharedDocs", "")
    buffer = s.directory_entries(items)
    whole = s.buffered_response(s.CMD_QUERY_DIRECTORY, 1, 2, 3, buffer)
    body = body_of(whole)
    declared = struct.unpack("<H", body[2:4])[0]
    bad += check("QUERY_DIRECTORY OutputBufferOffset is from the header",
                 declared == HEADER + 8, declared)
    bad += check("QUERY_DIRECTORY OutputBufferLength matches",
                 struct.unpack("<I", body[4:8])[0] == len(buffer))
    bad += check("QUERY_DIRECTORY buffer sits where it says",
                 whole[declared:declared + len(buffer)] == buffer)

    # Walk the entries the way a client does, by NextEntryOffset.
    names, position, steps = [], 0, 0
    while position < len(buffer) and steps < 500:
        steps += 1
        next_offset = struct.unpack("<I", buffer[position:position + 4])[0]
        name_length = struct.unpack("<I", buffer[position + 60:position + 64])[0]
        start = position + 94
        names.append(buffer[start:start + name_length].decode("utf-16le"))
        if next_offset == 0:
            break
        bad += check("entry offsets are 8-byte aligned", next_offset % 8 == 0,
                     next_offset)
        position += next_offset
    bad += check("every entry is reachable by walking the chain",
                 len(names) == len(items), f"{len(names)} of {len(items)}")
    bad += check("the listing has . and .. first",
                 names[:2] == [".", ".."], names[:2])
    bad += check("names survive the round trip",
                 "passwords.xlsx" in names, names)
    bad += check("the last entry terminates the chain",
                 struct.unpack("<I", buffer[position:position + 4])[0] == 0)

    # --- QUERY_INFO -------------------------------------------------------
    basic = s.file_info(0x04, 4096, False)
    bad += check("FileBasicInformation is 40 bytes",
                 basic is not None and len(basic) == 40,
                 len(basic) if basic else None)
    standard = s.file_info(0x05, 4096, True)
    bad += check("FileStandardInformation is 24 bytes",
                 standard is not None and len(standard) == 24,
                 len(standard) if standard else None)
    bad += check("FileStandardInformation flags a directory",
                 standard[21] == 1, standard[21] if standard else None)
    network = s.file_info(0x22, 4096, False)
    bad += check("FileNetworkOpenInformation is 56 bytes",
                 network is not None and len(network) == 56,
                 len(network) if network else None)
    bad += check("an unserved file class is refused, not guessed",
                 s.file_info(0xEE, 0, False) is None)

    bad += check("FileFsSizeInformation is 24 bytes",
                 len(s.filesystem_info(0x03)) == 24)
    bad += check("FileFsFullSizeInformation is 32 bytes",
                 len(s.filesystem_info(0x07)) == 32)
    bad += check("an unserved fs class is refused, not guessed",
                 s.filesystem_info(0xEE) is None)

    # --- the small fixed-shape replies ------------------------------------
    for command, size, label in ((s.CMD_ECHO, 4, "ECHO"),
                                 (s.CMD_FLUSH, 4, "FLUSH"),
                                 (s.CMD_SET_INFO, 2, "SET_INFO")):
        body = body_of(s.simple_response(command, 1, 2, 3, size))
        bad += check(f"{label} is {size} bytes and declares it",
                     len(body) == size
                     and struct.unpack("<H", body[0:2])[0] == size, len(body))

    # --- SESSION_SETUP: the guest flag is what makes a grant usable -------
    granted = s.session_setup_response(1, 2, b"", s.STATUS_SUCCESS,
                                       s.SESSION_FLAG_IS_GUEST)
    bad += check("a granted session reports success",
                 status_of(granted) == s.STATUS_SUCCESS)
    bad += check("a granted session is flagged guest so signing is not expected",
                 struct.unpack("<H", body_of(granted)[2:4])[0]
                 & s.SESSION_FLAG_IS_GUEST)
    challenge = s.session_setup_response(1, 2, s.ntlm_challenge_blob())
    bad += check("the challenge still asks for more processing",
                 status_of(challenge) == s.STATUS_MORE_PROCESSING)
    declared = struct.unpack("<H", body_of(challenge)[4:6])[0]
    bad += check("the security blob sits where SecurityBufferOffset says",
                 challenge[declared:declared + 8] == b"NTLMSSP\x00", declared)

    # --- path handling ----------------------------------------------------
    bad += check("the share root is a directory",
                 s.lookup_entry("SharedDocs", "") == (0, True))
    bad += check("a known file is found",
                 s.lookup_entry("SharedDocs", "passwords.xlsx") == (24576, False))
    bad += check("lookup is case-insensitive, like Windows",
                 s.lookup_entry("SharedDocs", "PASSWORDS.XLSX") is not None)
    bad += check("backslash paths resolve to their leaf",
                 s.lookup_entry("SharedDocs", "Finance\\2025") is not None)
    bad += check("an unknown file is absent rather than invented",
                 s.lookup_entry("SharedDocs", "nope.txt") is None)
    bad += check("opening a pipe on IPC$ succeeds",
                 s.lookup_entry("IPC$", "srvsvc") == (0, False))

    print()
    print("all checks passed" if not bad else f"{bad} check(s) failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
