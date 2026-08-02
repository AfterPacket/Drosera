"""Generate mutating malformed responses designed to crash or hang attacker tools.

Every crash is procedurally generated so no two are identical. A scanner that
adapts to one response gets a different one next time, and the mutation makes
it impossible to encode a static workaround.

The goal is resource exhaustion on their side:
- Malformed data forces parser loops and CPU burn
- Truncated responses hang clients waiting for completion
- Invalid protocol sequences break tool expectations
- Slow drip (via tarpit) ties up connection slots

Runs alongside tarpit, not instead of it. They get both slow drain and parsing
garbage.
"""

from __future__ import annotations

import os
import random
import string
from typing import Optional

# Off switch. Crash mode answers before the handshake, so an address in it
# stops producing credentials, transcripts and payloads for as long as it holds
# -- the same trade shared/fakeshell.py weighs for SCANBACK, and one an operator
# has to be able to decline without editing code.
ENABLED = os.getenv("HONEYPOT_CRASH", "1").strip().lower() not in (
    "0", "false", "no", "off", "")

GARBAGE_SIZE_MIN = int(os.getenv("HONEYPOT_CRASH_GARBAGE_MIN", "512"))
GARBAGE_SIZE_MAX = int(os.getenv("HONEYPOT_CRASH_GARBAGE_MAX", "8192"))


def enabled() -> bool:
    """Whether crash mode may engage.

    Read by identity.is_crashed() as well as by activate_crash(), so turning
    this off releases every address already flagged rather than stranding them
    for the rest of the identity's 7-day TTL.
    """
    return ENABLED


# Protocol-agnostic garbage generators. Each produces unparseable data
# in a different way, so even if they fix one, the next response is different.


def _garbage() -> bytes:
    """Random bytes designed to confuse parsers."""
    size = random.randint(GARBAGE_SIZE_MIN, GARBAGE_SIZE_MAX)
    # Mix of valid printable (to avoid trivial rejection) and binary
    data = []
    for _ in range(size):
        if random.random() < 0.7:
            data.append(random.choice(string.printable[:-5]).encode()[0])  # no whitespace
        else:
            data.append(random.randint(0, 255))
    return bytes(data)


def _truncated_valid_then_garbage(valid: bytes) -> bytes:
    """Send valid data followed by abrupt garbage. Parsers expecting more hang."""
    cut = random.randint(len(valid) // 2, len(valid))
    return valid[:cut] + _garbage()


def _repeated_null_bytes() -> bytes:
    """Null bytes confuse C string handling and buffer management."""
    return b"\x00" * random.randint(100, 1000)


def _alternating_valid_invalid() -> bytes:
    """Alternate between valid-looking and completely invalid bytes."""
    chunks = []
    for _ in range(random.randint(10, 50)):
        if random.random() < 0.5:
            chunks.append(os.urandom(random.randint(1, 20)))
        else:
            chunks.append(random.choice([
                b"HTTP/1.1 200 OK\r\n",
                b"Content-Length: 999999\r\n",
                b"\xff\xfe\xfd\xfc",
                b"...",
            ]))
    return b"".join(chunks)


def _invalid_encoding() -> bytes:
    """UTF-8 continuation bytes without a valid start byte, etc."""
    invalid = [b"\x80", b"\xc0", b"\xc1", b"\xfe", b"\xff"]
    chunks = []
    for _ in range(random.randint(50, 200)):
        if random.random() < 0.7:
            chunks.append(random.choice(invalid))
        else:
            chunks.append(bytes([random.randint(32, 126)]))
    return b"".join(chunks)


def _loop_inducing() -> bytes:
    """Pattern that might cause infinite loops in naive parsers."""
    # Repeated size headers that don't match content
    pattern = b"Content-Length: 1000\r\n\r\nX"
    return pattern * random.randint(10, 50)


def _partial_headers() -> bytes:
    """Valid HTTP header prefix, no termination."""
    headers = [
        b"HTTP/1.1 200 OK\r\nContent-Type: ",
        b"Content-Length: " + str(random.randint(1000000, 9999999)).encode(),
        b"Transfer-Encoding: chunked\r\n",
        b"Set-Cookie: session=",
    ]
    result = b"".join(random.sample(headers, random.randint(1, len(headers))))
    return result  # Never sends the final \r\n\r\n


def _binary_soup() -> bytes:
    """Completely random binary data."""
    return os.urandom(random.randint(100, 2048))


GENERATORS = [
    _garbage,
    _repeated_null_bytes,
    _alternating_valid_invalid,
    _invalid_encoding,
    _loop_inducing,
    _partial_headers,
    _binary_soup,
]


def for_protocol(protocol: str, valid_response: Optional[bytes] = None) -> bytes:
    """Generate a crash for a specific protocol.

    Combines protocol-agnostic garbage with protocol-specific malformations.
    valid_response is a correct response for this protocol; we'll truncate it
    and append garbage.
    """
    result = random.choice(GENERATORS)()

    # If we have a valid response for this protocol, truncate and append garbage
    if valid_response:
        result = _truncated_valid_then_garbage(valid_response)

    # Add an extra layer of confusion: random mutation
    if random.random() < 0.5:
        result = result[:len(result)//2] + _garbage()

    return result


def http_crash(method: str = "GET") -> bytes:
    """Malformed HTTP response designed to crash scanners."""
    # Start with something that looks like HTTP, then corrupt it
    valid = b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"
    crash = for_protocol("http", valid)

    # Mix in some protocol-specific weirdness
    if random.random() < 0.5:
        crash = b"HTTP/1.1 " + os.urandom(100) + b"\r\n" + crash

    return crash


def ssh_crash() -> bytes:
    """Malformed SSH protocol data.

    SSH starts with version string; malform everything after that.
    """
    valid = b"SSH-2.0-OpenSSH_8.0\r\n"
    return valid + for_protocol("ssh")


def telnet_crash() -> bytes:
    """Malformed telnet with control sequences."""
    # Invalid IAC (Interpret As Command) sequences
    valid = b"Welcome\r\n"
    crash = for_protocol("telnet", valid)

    # Sprinkle IAC bytes that make no sense
    for _ in range(random.randint(5, 15)):
        pos = random.randint(0, len(crash) - 1)
        crash = crash[:pos] + bytes([0xff]) + crash[pos:]  # IAC

    return crash


def mysql_crash() -> bytes:
    """Malformed MySQL protocol.

    MySQL uses length-prefixed packets; corrupt the length or payload.
    """
    # Valid MySQL handshake start, then garbage
    valid = b"\x0a\x08\x00\x00\x00"  # protocol 10, server version
    crash = for_protocol("mysql", valid)

    # Corrupted length prefix
    if random.random() < 0.5:
        crash = bytes([random.randint(0, 255)] * 4) + os.urandom(1000)

    return crash


def smb_crash() -> bytes:
    """Malformed SMB protocol.

    SMB has strict packet structure; we'll violate it.
    """
    # SMB signature: \xff\x53\x4d\x42
    crash = b"\xff\x53\x4d\x42"
    crash += for_protocol("smb")
    return crash


# Map protocol to crash generator
PROTOCOL_CRASHES = {
    "http": http_crash,
    "https": http_crash,
    "ssh": ssh_crash,
    "telnet": telnet_crash,
    "mysql": mysql_crash,
    "smb": smb_crash,
}


def get_crash(protocol: str) -> bytes:
    """Get a crash response for a protocol. Falls back to generic if not mapped."""
    generator = PROTOCOL_CRASHES.get(protocol.lower(), lambda: for_protocol(protocol))
    return generator()
