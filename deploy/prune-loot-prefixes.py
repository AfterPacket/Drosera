#!/usr/bin/env python3
"""Remove partial samples left by the pre-fix capture-on-every-append bug.

Until "Capture the dropper, not eleven prefixes of it", shared/fakeshell.py
quarantined a file on every redirection rather than once per file. A busybox
loader assembled the way they all are --

    echo -ne "\\x23\\x21..." > .k
    echo -ne "..." >> .k          (x10)

-- therefore left eleven samples, ten of them prefixes of a file that has never
existed anywhere else. They are indistinguishable from real captures on the
loot page, and each one takes a VirusTotal lookup from a budget of a few
hundred a day to be told, correctly, that nobody has ever seen it.

This deletes only samples that are a *strict byte prefix* of another sample
written by the same address to the same path. That is a much narrower claim
than "looks truncated": if the bytes are not literally the opening of a longer
capture from the same source, the sample stays.

Loot is append-only evidence and this is the one thing that deletes any of it,
so it prints and stops unless you pass --apply.

    sudo ./deploy/prune-loot-prefixes.py                  # what would go
    sudo ./deploy/prune-loot-prefixes.py --ip 1.2.3.4     # one address
    sudo ./deploy/prune-loot-prefixes.py --apply          # do it

Needs write on storage/loot, which is 0700 owned by the honeypot UID -- so
sudo, or run it as that user. Stop nothing: the intel sidecar rereads the
directory every poll and a sample vanishing between polls is already handled.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

LOOT_DIR = Path(os.getenv("LOOT_DIR", "storage/loot"))

# The fake tree caps a written file at 8192 bytes, so nothing this bug produced
# is larger. Reading every multi-megabyte binary in the quarantine to compare
# prefixes would be both pointless and a good way to run the box out of memory.
MAX_CONSIDERED = 8192


def load(loot_dir):
    """Samples that could plausibly be shell-write fragments, as sha -> record."""
    out = {}
    for meta_file in sorted(loot_dir.glob("*.json")):
        digest = meta_file.stem
        blob = loot_dir / f"{digest}.bin"
        if not blob.is_file():
            continue
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        sightings = meta.get("sightings") or []
        if not sightings:
            continue
        # Every sighting, not any: a sample that also arrived over SFTP, or from
        # a second address, is corroborated by something this bug cannot explain.
        if not all(s.get("origin") == "shell-write" for s in sightings):
            continue
        try:
            if blob.stat().st_size > MAX_CONSIDERED:
                continue
            data = blob.read_bytes()
        except OSError:
            continue

        out[digest] = {
            "data": data,
            "meta_file": meta_file,
            "blob": blob,
            "sightings": sightings,
            "scanned": bool(meta.get("scan")),
        }
    return out


def prefixes(samples, only_ip=None):
    """(victim, survivor) pairs where victim's bytes open survivor's."""
    # Grouped by the pair that identifies one assembly: one address building one
    # path. Two addresses dropping the same loader are independent captures even
    # when one got further than the other.
    groups = defaultdict(set)
    for digest, rec in samples.items():
        for sighting in rec["sightings"]:
            ip = sighting.get("ip") or ""
            if only_ip and ip != only_ip:
                continue
            groups[(ip, sighting.get("filename") or "")].add(digest)

    doomed = {}
    complete = set()
    for (ip, filename), digests in sorted(groups.items()):
        ordered = sorted(digests, key=lambda d: len(samples[d]["data"]))
        for index, digest in enumerate(ordered):
            data = samples[digest]["data"]
            for longer in ordered[index + 1:]:
                other = samples[longer]["data"]
                if len(other) > len(data) and other.startswith(data):
                    doomed[digest] = (longer, ip, filename)
                    break
            else:
                # Nothing in this group extends it, so for this address at this
                # path it is the finished article.
                complete.add(digest)

    # Deduplication means one blob can belong to several groups. A short script
    # that one address finished and another address's longer drop happens to
    # open with is a real capture wearing a prefix's clothes -- being complete
    # anywhere outranks being partial somewhere else.
    return {d: v for d, v in doomed.items() if d not in complete}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--loot-dir", default=str(LOOT_DIR))
    parser.add_argument("--ip", default="", help="restrict to one source address")
    parser.add_argument("--apply", action="store_true",
                        help="actually delete; without it nothing is touched")
    args = parser.parse_args()

    loot_dir = Path(args.loot_dir)
    if not loot_dir.is_dir():
        print(f"no such directory: {loot_dir}", file=sys.stderr)
        return 2

    samples = load(loot_dir)
    doomed = prefixes(samples, only_ip=args.ip or None)
    if not doomed:
        print(f"{len(samples)} shell-write sample(s) examined, no prefixes found.")
        return 0

    freed = 0
    for digest, (survivor, ip, filename) in sorted(
            doomed.items(), key=lambda kv: (kv[1][1], len(samples[kv[0]]["data"]))):
        size = len(samples[digest]["data"])
        freed += size
        flag = " [scanned]" if samples[digest]["scanned"] else ""
        print(f"{digest[:16]}  {size:>6}B  {ip}  {filename}{flag}"
              f"\n{'':18}-> opens {survivor[:16]} "
              f"({len(samples[survivor]['data'])}B)")

    print(f"\n{len(doomed)} partial sample(s), {freed}B")
    if not args.apply:
        print("Nothing deleted. Re-run with --apply.")
        return 0

    removed = 0
    for digest in doomed:
        try:
            samples[digest]["blob"].unlink()
            samples[digest]["meta_file"].unlink()
            removed += 1
        except OSError as exc:
            print(f"could not remove {digest[:16]}: {exc}", file=sys.stderr)
    print(f"Removed {removed}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
