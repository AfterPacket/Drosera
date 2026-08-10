#!/usr/bin/env python3
"""Say which captured samples have trustworthy bytes, and which do not.

Three bugs fixed in "Capture the dropper, not eleven prefixes of it" changed
what landed on disk for samples that arrived through the fake shell. Anything
captured before that commit may not be the file the attacker actually built:

  * the trailing newline was stripped from every `echo`-written file, and -n
    was parsed then ignored, so a script is often one byte short
  * bare octal escapes (`\\3B`, a typo for `\\x3B` seen in the wild) were stored
    as three literal characters where busybox writes two
  * loot was captured on every append, so one dropper assembled over eleven
    writes produced eleven samples, ten of them prefixes

A hash computed over any of those is an indicator of this honeypot rather than
of the malware. Nobody else will ever match it. That matters most where the
hash is republished, which is the whole point of the threat-intel feed -- so
this exists to say, per sample, whether its bytes can be quoted.

How a sample arrived decides it:

    loader-fetch   byte-exact.  HTTP response body, straight to quarantine.
    sftp-put       byte-exact.  Raw upload stream.
    shell-write    suspect.     Went through the fake shell's echo handling.

Read-only. It reports and changes nothing.

    sudo ./deploy/verify-loot-provenance.py
    sudo ./deploy/verify-loot-provenance.py --hashes published.txt
    sudo ./deploy/verify-loot-provenance.py --suspect-only --format csv
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

LOOT_DIR = Path(os.getenv("LOOT_DIR", "storage/loot"))

# Origins whose bytes never passed through the fake shell.
EXACT_ORIGINS = {"loader-fetch", "sftp-put", "http-upload"}

# The fake tree caps a written file at 8192 bytes, so nothing the append bug
# produced is larger; reading every multi-megabyte ELF to compare prefixes
# would be pointless and a good way to exhaust memory on a small VPS.
MAX_PREFIX_CHECK = 8192

# A backslash followed by an octal digit, in text. Before the fix this is what
# an undecoded `\3B` looks like on disk; after it, the byte is decoded and this
# pattern does not survive. Its presence in a shell-write sample is direct
# evidence rather than inference.
OCTAL_ARTEFACT = re.compile(rb"\\[1-7]")

BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\x1f\x8b", b"BZh", b"PK\x03\x04",
                b"\xfd7zXZ\x00", b"\xca\xfe\xba\xbe")


def looks_text(data: bytes) -> bool:
    head = data[:4096]
    if not head or head.startswith(BINARY_MAGIC) or b"\x00" in head:
        return False
    printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D, 0x1B}
    return sum(1 for b in head if b not in printable) / len(head) <= 0.10


def load(loot_dir: Path, wanted: set) -> dict:
    out = {}
    for meta_file in sorted(loot_dir.glob("*.json")):
        digest = meta_file.stem
        if wanted and digest not in wanted:
            continue
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        blob = loot_dir / f"{digest}.bin"
        data = b""
        try:
            if blob.stat().st_size <= MAX_PREFIX_CHECK:
                data = blob.read_bytes()
            size = blob.stat().st_size
        except OSError:
            size = int(meta.get("size") or 0)

        sightings = meta.get("sightings") or []
        origins = {str(s.get("origin") or "?") for s in sightings}
        out[digest] = {
            "origins": origins,
            "size": size,
            "data": data,
            "sightings": len(sightings),
            "ips": sorted({s.get("ip") for s in sightings if s.get("ip")}),
            "filenames": sorted({s.get("filename") for s in sightings
                                 if s.get("filename")}),
            "lineage": next((s.get("lineage") for s in sightings
                             if s.get("lineage")), None),
        }
    return out


def classify(record: dict) -> tuple:
    """(verdict, [reasons]). Verdict is EXACT, SUSPECT or UNKNOWN."""
    origins = record["origins"]
    reasons = []

    if not origins or origins == {"?"}:
        return "UNKNOWN", ["no origin recorded in any sighting"]

    shell = {o for o in origins if o not in EXACT_ORIGINS}
    if not shell:
        return "EXACT", [f"arrived via {', '.join(sorted(origins))}"]

    reasons.append(f"arrived via {', '.join(sorted(shell))}")

    data = record["data"]
    if data and looks_text(data):
        # Direct evidence, where the bytes still show it.
        if OCTAL_ARTEFACT.search(data):
            match = OCTAL_ARTEFACT.search(data).group(0)
            reasons.append(
                f"contains an undecoded octal escape ({match!r}) -- these bytes "
                f"are the honeypot's, not the attacker's")
        if not data.endswith(b"\n"):
            reasons.append(
                "does not end with a newline -- the echo path stripped it, so "
                "this file is probably one byte short")
    return "SUSPECT", reasons


def find_prefixes(records: dict) -> dict:
    """digest -> the longer sample it is an opening of, within one source."""
    groups = defaultdict(set)
    for digest, rec in records.items():
        if not rec["data"]:
            continue
        for ip in rec["ips"] or ["?"]:
            for name in rec["filenames"] or ["?"]:
                groups[(ip, name)].add(digest)

    doomed, complete = {}, set()
    for _, digests in groups.items():
        ordered = sorted(digests, key=lambda d: len(records[d]["data"]))
        for index, digest in enumerate(ordered):
            data = records[digest]["data"]
            for longer in ordered[index + 1:]:
                other = records[longer]["data"]
                if len(other) > len(data) and other.startswith(data):
                    doomed[digest] = longer
                    break
            else:
                complete.add(digest)
    return {d: v for d, v in doomed.items() if d not in complete}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--loot-dir", default=str(LOOT_DIR))
    parser.add_argument("--hashes", help="file of SHA-256s, one per line; "
                                         "restricts the report to those")
    parser.add_argument("--suspect-only", action="store_true")
    parser.add_argument("--format", choices=["text", "csv"], default="text")
    args = parser.parse_args()

    loot_dir = Path(args.loot_dir)
    if not loot_dir.is_dir():
        print(f"no such directory: {loot_dir}", file=sys.stderr)
        return 2

    wanted = set()
    if args.hashes:
        try:
            for line in Path(args.hashes).read_text(encoding="utf-8").splitlines():
                token = line.strip().split()[0] if line.strip() else ""
                if len(token) == 64:
                    wanted.add(token.lower())
        except OSError as exc:
            print(f"cannot read {args.hashes}: {exc}", file=sys.stderr)
            return 2

    records = load(loot_dir, wanted)
    if not records:
        print("no matching samples found", file=sys.stderr)
        return 1

    prefixes = find_prefixes(records)
    rows = []
    for digest, rec in sorted(records.items(), key=lambda kv: -kv[1]["size"]):
        verdict, reasons = classify(rec)
        if digest in prefixes:
            verdict = "SUSPECT"
            reasons.append(f"is a byte-for-byte opening of "
                           f"{prefixes[digest][:16]} -- an append-bug fragment, "
                           f"not a file that ever existed")
        rows.append((digest, verdict, rec, reasons))

    if args.hashes:
        missing = wanted - set(records)
        for digest in sorted(missing):
            rows.append((digest, "MISSING", None, ["not in this loot store"]))

    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["sha256", "verdict", "size", "sightings", "origins",
                         "reasons"])
        for digest, verdict, rec, reasons in rows:
            if args.suspect_only and verdict == "EXACT":
                continue
            writer.writerow([digest, verdict,
                             rec["size"] if rec else "",
                             rec["sightings"] if rec else "",
                             "|".join(sorted(rec["origins"])) if rec else "",
                             "; ".join(reasons)])
        return 0

    counts = defaultdict(int)
    for digest, verdict, rec, reasons in rows:
        counts[verdict] += 1
        if args.suspect_only and verdict == "EXACT":
            continue
        size = f"{rec['size']}B" if rec else "-"
        print(f"\n{digest}\n  {verdict:<8} {size:>10}"
              + (f"  {rec['sightings']} sighting(s)" if rec else ""))
        for reason in reasons:
            print(f"           - {reason}")
        if rec and rec["lineage"]:
            parent = str(rec["lineage"].get("parent_sha256") or "")[:16]
            print(f"           - stage {rec['lineage'].get('depth')} of {parent}")

    print("\n" + "-" * 70)
    print(f"  {counts['EXACT']:>4} EXACT    bytes are the attacker's; safe to publish")
    print(f"  {counts['SUSPECT']:>4} SUSPECT  bytes may be this honeypot's; do not "
          f"republish the hash")
    if counts["UNKNOWN"]:
        print(f"  {counts['UNKNOWN']:>4} UNKNOWN  no origin recorded")
    if counts["MISSING"]:
        print(f"  {counts['MISSING']:>4} MISSING  listed but not in the store")
    print()
    if counts["SUSPECT"]:
        print("For each SUSPECT sample the finding still stands -- what it did and")
        print("what it named are unaffected. It is the *hash* that cannot be")
        print("quoted, because it is a hash of what we wrote rather than of what")
        print("they sent. Re-derive from payload_excerpt in the event log if you")
        print("need the real bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
