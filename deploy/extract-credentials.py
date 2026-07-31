#!/usr/bin/env python3
"""Build the accepted-password list from this deployment's own captured logins.

Two reasons this is not a list written in advance and shipped in the repo.

First, a published accept-list is the weakness it defends against. Anyone can
read `COMMON_PASSWORDS` in shared/credentials.py, choose a password that is not
in it, and use that as an accept-all probe -- exactly the attack that cost us
an engagement at 20:21. The persona is per-deployment for the same reason.

Second, the honeypot already knows the answer. A week of traffic is a better
account of what is actually being sprayed at this host than any guess.

The signal is how many DISTINCT addresses tried a password, not how many times
it was tried:

  * Many sources    -> it is in the real spray lists, so a genuinely weak box
                       would fall to it, so accepting it is honest.
  * A single source -> could be anything, including a probe. One scanner
                       hammering one string proves nothing about the string.

Generated-looking strings are dropped regardless of how popular they are: a
probe used by fifty scanners is still a probe, and accepting it identifies the
honeypot fifty times over.

Usage:

    python3 deploy/extract-credentials.py                  # report only
    python3 deploy/extract-credentials.py --write          # write the list

Output goes to storage/credentials/accepted.txt, which is gitignored along with
the rest of storage/. Captured passwords are frequently reused from prior
breaches and may belong to other victims -- this file must not be published.
"""

import argparse
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import credentials  # noqa: E402

LOG_DIR = ROOT / "storage" / "logs"
OUT_FILE = ROOT / "storage" / "credentials" / "accepted.txt"


def collect(log_dir: pathlib.Path):
    """password -> set of source addresses that tried it."""
    sources = collections.defaultdict(set)
    attempts = collections.Counter()
    files = sorted(log_dir.glob("*.jsonl*"))
    if not files:
        return sources, attempts, files

    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or "CREDENTIAL_ATTEMPT" not in line:
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if event.get("event_type") != "CREDENTIAL_ATTEMPT":
                        continue
                    payload = event.get("payload_excerpt") or ""
                    if ":" not in payload:
                        continue
                    # Split once from the left: a password may contain colons,
                    # a username may not.
                    _, password = payload.split(":", 1)
                    password = password.strip()
                    if not password:
                        continue
                    sources[password].add(event.get("real_ip") or "")
                    attempts[password] += 1
        except OSError:
            continue
    return sources, attempts, files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-sources", type=int, default=3,
                        help="distinct addresses that must have tried a "
                             "password before it is accepted (default 3)")
    parser.add_argument("--limit", type=int, default=500,
                        help="most-seen passwords to keep (default 500)")
    parser.add_argument("--write", action="store_true",
                        help="write the list; otherwise just report")
    args = parser.parse_args()

    sources, attempts, files = collect(LOG_DIR)
    if not files:
        print(f"No logs in {LOG_DIR}. Nothing to do.")
        return 1

    ranked = sorted(sources.items(), key=lambda item: (-len(item[1]), item[0]))
    keep, dropped_rare, dropped_generated = [], 0, 0
    for password, addresses in ranked:
        if len(addresses) < args.min_sources:
            dropped_rare += 1
            continue
        if credentials.looks_generated(password):
            dropped_generated += 1
            continue
        keep.append((password, len(addresses), attempts[password]))
        if len(keep) >= args.limit:
            break

    print(f"read {len(files)} log file(s)")
    print(f"{len(sources)} distinct passwords, "
          f"{sum(attempts.values())} attempts")
    print(f"keeping {len(keep)} seen from >= {args.min_sources} addresses")
    print(f"dropped {dropped_rare} seen from fewer sources")
    print(f"dropped {dropped_generated} that look machine-generated")
    print()
    print(f"{'sources':>8}  {'tries':>6}  password")
    for password, source_count, attempt_count in keep[:25]:
        print(f"{source_count:>8}  {attempt_count:>6}  {password}")
    if len(keep) > 25:
        print(f"{'':>8}  {'':>6}  ... and {len(keep) - 25} more")

    if not args.write:
        print()
        print("Report only. Re-run with --write to save.")
        return 0

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as handle:
        handle.write("# Accepted passwords for this deployment, built by\n"
                     "# deploy/extract-credentials.py from captured logins.\n"
                     "#\n"
                     "# Sensitive: these are real credentials, frequently\n"
                     "# reused from prior breaches, and may belong to other\n"
                     "# victims. Do not publish and do not test anywhere.\n")
        for password, source_count, attempt_count in keep:
            handle.write(f"{password}\n")
    print()
    print(f"wrote {len(keep)} passwords to {OUT_FILE}")
    print("Set HONEYPOT_ACCEPT_WORDLIST=/var/honeypot/storage/credentials/"
          "accepted.txt and restart to use it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
