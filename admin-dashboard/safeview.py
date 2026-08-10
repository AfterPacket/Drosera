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

from typing import Any, Dict

# Enough to recognise anything, far short of what a browser wants to be handed
# in one response. A sample can be 16MB; nobody reads 16MB in a modal.
MAX_VIEW_BYTES = 256 * 1024

# How much to judge text-or-binary by. A script declares itself immediately.
SNIFF_BYTES = 8192

MAX_NONPRINTABLE = 0.10

BINARY_MAGIC = (
    b"\x7fELF", b"MZ", b"\x1f\x8b", b"BZh", b"PK\x03\x04",
    b"\xfd7zXZ\x00", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe", b"\x1bLua", b"%PDF",
)

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


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


def view(data: bytes, *, force_hex: bool = False,
         total_size: int = 0) -> Dict[str, Any]:
    """A sample, rendered for display. Never raises on content.

    `total_size` is the size on disk, which may exceed what was read -- the
    caller reads at most MAX_VIEW_BYTES and the difference is what `truncated`
    reports.
    """
    data = bytes(data or b"")
    shown = len(data)
    size = int(total_size or shown)
    binary = force_hex or looks_binary(data)

    if binary:
        content = hexdump(data)
    else:
        content = defang(data.decode("utf-8", "replace"))

    return {
        "kind": "binary" if binary else "text",
        "forced": bool(force_hex),
        "content": content,
        "bytes_shown": shown,
        "size": size,
        "truncated": shown < size,
        "lines": content.count("\n") + 1 if content else 0,
    }
