"""Render a captured sample into something safe to put on a screen.

Reading a payload is the most ordinary thing an operator wants to do with the
quarantine, and every obvious way of doing it is a bad idea. `less` hands the
file to `lesspipe`, which picks an external decoder by type. `vim` has executed
code from a modeline. `cat` sends whatever ANSI the attacker wrote straight at
your terminal, and terminals have historically been persuaded by escape
sequences to echo text back into the input buffer. `strings` parses the file
through BFD first. All of those turn "look at it" into "parse it with something
that has a CVE history", against bytes chosen by the person you are
investigating.

So nothing here parses anything. There is no subprocess, no library that
understands file formats, and no code path that treats the content as anything
but bytes. Three independent things have to fail before a sample can affect the
operator:

  * control characters are rewritten to caret notation here, so no escape
    sequence survives into a terminal or a copy-paste
  * the caller returns this as JSON and the page inserts it with textContent,
    so nothing is ever parsed as markup
  * the dashboard's CSP is `script-src 'self'` with no unsafe-inline, so
    injected script would not run even if it reached the DOM

Any one of those is probably enough. The point of having all three is that
"probably" is doing real work in that sentence.
"""

from typing import Any, Dict, List, Optional

# Enough to recognise anything, far short of what a browser wants to be handed
# in one response. A sample can be 16MB; nobody reads 16MB in a modal.
MAX_VIEW_BYTES = 256 * 1024

# Hex is capped far lower than text, because the two cost wildly different
# amounts to render the same input. A byte of text is a character; a byte of
# hexdump is about five, and 16 of them make a line. 256KB of script is a long
# script. 256KB dumped as hex is 16,384 lines and 1.2MB of DOM, which is not a
# view of the sample -- it is a denial of service against the operator's
# browser. 4KB is 256 lines: enough to identify a file from its header, which
# is all hex is good for here. Reading the *content* of a binary is what the
# strings view is for.
MAX_HEX_BYTES = 4 * 1024

# How much to judge text-or-binary by. A script declares itself immediately.
SNIFF_BYTES = 8192

MAX_NONPRINTABLE = 0.10

# Shortest run worth showing. `strings` uses 4 and so does this: raising it to
# 6 would cut accidental runs by about sevenfold, but it would also drop
# "root", "admin", "sh" and "1234" -- which in a Mirai sample are not noise,
# they are the credential table, and that is exactly what an operator is
# looking for.
MIN_STRING = 4

# How many runs before the list stops being something a person scrolls. Set
# high deliberately: the cap is consumed in file order, so a low one does not
# trim the tail, it silently stops before .rodata -- and .rodata is where the
# C2 addresses and paths live. A run is a short line, so even the ceiling
# costs less DOM than the hexdump this replaces.
MAX_STRINGS = 8000

# Strings reads past MAX_VIEW_BYTES. The other two modes are bounded by what a
# person can look at; this one is bounded by where the interesting bytes are,
# and in a stripped ELF that is the far end of the file. Scanning is a loop
# over integers, so the cost is trivial next to being handed the first 40% of
# a binary and told that is all of it.
MAX_STRINGS_SCAN = 16 * 1024 * 1024

BINARY_MAGIC = (
    b"\x7fELF", b"MZ", b"\x1f\x8b", b"BZh", b"PK\x03\x04",
    b"\xfd7zXZ\x00", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe", b"\x1bLua", b"%PDF",
)

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# e_machine values, which is the field that matters for this appliance: a
# dropper that fetches eleven binaries is fetching one per architecture, and
# the architecture is the only thing distinguishing them. The list is the set
# of targets Mirai and its descendants actually build for.
_ELF_MACHINES = {
    0x02: "SPARC", 0x03: "x86", 0x04: "m68k", 0x08: "MIPS",
    0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390", 0x28: "ARM",
    0x2A: "SuperH", 0x2B: "SPARCv9", 0x32: "IA-64", 0x3E: "x86-64",
    0x53: "AVR", 0x5A: "Xtensa", 0xB7: "AArch64", 0xF3: "RISC-V",
}
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}


def looks_binary(data: bytes) -> bool:
    head = bytes(data[:SNIFF_BYTES])
    if not head:
        return False
    if head.startswith(BINARY_MAGIC) or b"\x00" in head:
        return True
    nonprintable = sum(1 for byte in head if byte not in _PRINTABLE)
    return (nonprintable / len(head)) > MAX_NONPRINTABLE


def defang(text: str) -> str:
    """Rewrite control characters so they are visible rather than active.

    This is the security property, not a display nicety. `\\x1b` is what makes
    an escape sequence an escape sequence; shown as `^[` it is two harmless
    characters. Tabs and newlines survive because they are what makes a script
    readable, and neither is an attack.

    Carriage return is deliberately *not* spared. A lone `\\r` lets a line
    overwrite the one before it, which is how a payload hides its real content
    from someone skim-reading -- exactly the reader this exists to protect.
    """
    out = []
    for char in text:
        code = ord(char)
        if char in ("\n", "\t"):
            out.append(char)
        elif code < 0x20:
            out.append("^" + chr(code + 0x40))
        elif code == 0x7F:
            out.append("^?")
        else:
            out.append(char)
    return "".join(out)


def hexdump(data: bytes, *, base: int = 0) -> str:
    """Canonical hex + ASCII. Non-printables are dots, never themselves."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        octets = " ".join(f"{b:02x}" for b in chunk[:8])
        tail = " ".join(f"{b:02x}" for b in chunk[8:])
        gap = "  " if tail else " "
        rendered = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + offset:08x}  {octets:<23}{gap}{tail:<23}  |{rendered}|")
    return "\n".join(lines)


def strings(data: bytes, *, minimum: int = MIN_STRING,
            limit: int = MAX_STRINGS) -> List[str]:
    """Printable runs, the way `strings` would if `strings` were safe.

    The real `strings` opens the file with BFD, which parses section headers
    before it prints anything -- a full object-file parser, in C, pointed at
    bytes an attacker chose. This is a loop over integers. It cannot be steered
    into anything because there is nothing to steer.

    The output needs no defanging: a run is built only from bytes in
    0x20..0x7E, so a control character cannot appear in the result by
    construction rather than by filtering. That is a stronger property than
    defang() gives, and it is why this returns a list of already-safe lines.

    This is the view that answers the question an operator actually has about
    a captured ELF -- where does it call home, what does it kill, which
    credentials does it carry -- none of which a hexdump will ever tell them.
    """
    found: List[str] = []
    run = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            run.append(byte)
            continue
        if len(run) >= minimum:
            found.append(run.decode("ascii"))
            if len(found) >= limit:
                return found
        run.clear()
    if len(run) >= minimum and len(found) < limit:
        found.append(run.decode("ascii"))
    return found


def describe(data: bytes) -> Optional[str]:
    """One line naming the file format, from fixed offsets and a dict.

    Reading five bytes at known indices and looking two integers up in a table
    is not parsing in the sense the module docstring warns about: there is no
    format-driven control flow, no seeking to an attacker-supplied offset, and
    no allocation sized by the file. The worst a hostile header achieves is a
    wrong label.

    Worth the twenty lines because it collapses the question these samples
    exist to answer. Eleven near-identical binaries from one dropper are eleven
    architectures, and until now the dashboard called all of them "binary".
    """
    if len(data) < 20 or not data.startswith(b"\x7fELF"):
        if data.startswith(b"MZ"):
            return "PE/DOS executable"
        if data.startswith(b"\x1f\x8b"):
            return "gzip"
        if data.startswith(b"PK\x03\x04"):
            return "zip"
        if data.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
                            b"\xce\xfa\xed\xfe")):
            return "Mach-O"
        if data.startswith(b"%PDF"):
            return "PDF"
        if data.startswith(b"\x1bLua"):
            return "Lua bytecode"
        return None

    bits = {1: "32-bit", 2: "64-bit"}.get(data[4], "?-bit")
    big = data[5] == 2
    order = "big-endian" if big else "little-endian"
    fields = "big" if big else "little"
    e_type = int.from_bytes(data[16:18], fields)
    machine = int.from_bytes(data[18:20], fields)

    arch = _ELF_MACHINES.get(machine, f"machine {machine:#x}")
    kind = _ELF_TYPES.get(e_type, f"type {e_type}")
    return f"ELF {bits} {arch} {order} {kind}"


def view(data: bytes, *, mode: str = "auto", total_size: int = 0) -> Dict[str, Any]:
    """A sample, rendered for display. Never raises on content.

    `total_size` is the size on disk, which may exceed what was read -- the
    caller reads at most MAX_VIEW_BYTES and the difference is what `truncated`
    reports. `bytes_shown` is what this mode actually rendered, which for hex
    is smaller again.
    """
    data = bytes(data or b"")
    read = len(data)
    size = int(total_size or read)
    binary = looks_binary(data)
    label = describe(data)

    if mode == "strings":
        found = strings(data)
        content = "\n".join(found)
        kind = "strings"
        shown = read
        if len(found) >= MAX_STRINGS:
            kind = "strings (truncated)"
    elif mode == "hex" or (mode == "auto" and binary):
        shown = min(read, MAX_HEX_BYTES)
        content = hexdump(data[:shown])
        kind = "binary"
    else:
        content = defang(data.decode("utf-8", "replace"))
        kind = "text"
        shown = read

    return {
        "kind": kind,
        "mode": mode,
        "binary": binary,
        "format": label,
        "content": content,
        "bytes_shown": shown,
        "size": size,
        "truncated": shown < size,
        "lines": content.count("\n") + 1 if content else 0,
    }
