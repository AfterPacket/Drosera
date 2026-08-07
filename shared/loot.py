"""Quarantine for whatever an attacker hands us.

Nothing here executes, decompresses, parses, or interprets a captured file. It
is bytes on disk and a hash, and that is deliberate: the moment a honeypot
starts *understanding* attacker input it acquires the attack surface of
whatever library does the understanding. Analysis happens elsewhere, on
something you are willing to lose.

The safety properties, all of which matter:

  * Content-addressed. The filename is the SHA-256 of the content, so an
    attacker never influences a path. This is the single most important
    property here -- `../../etc/cron.d/x` as a filename is otherwise a real
    write primitive.
  * Never executable. Files land 0400, the directory 0700, and nothing in the
    tree is on a PATH or under a document root. nginx already refuses to serve
    anything under storage/.
  * Bounded. Per-file and total caps, checked before writing, so a large upload
    cannot fill the disk and take the box down -- which is a denial of service
    an attacker can trigger deliberately.
  * Deduplicated. The same payload from fifty hosts is one file and fifty
    sightings, which is also the more useful shape for answering "who else
    dropped this".

Written by the honeypot containers, which have no egress. Read by the intel
sidecar, which has egress but no listening ports.
"""

import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

LOOT_DIR = Path(os.getenv("LOOT_DIR", "/var/honeypot/storage/loot"))

# A dropper is kilobytes. A miner is megabytes. Past that it is either a disk
# attack or something too big to be interesting, and both get truncated.
MAX_FILE_BYTES = int(os.getenv("LOOT_MAX_FILE_BYTES", str(16 * 1024 * 1024)))
MAX_TOTAL_MB = int(os.getenv("LOOT_MAX_TOTAL_MB", "2048"))

# Below this it is a probe, not a payload: the `echo xxxxxx` capability tests
# would otherwise bury the real samples under thousands of identical stubs.
MIN_FILE_BYTES = int(os.getenv("LOOT_MIN_FILE_BYTES", "24"))

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _total_bytes() -> int:
    try:
        return sum(f.stat().st_size for f in LOOT_DIR.glob("*.bin"))
    except OSError:
        return 0


def _ensure_dir() -> bool:
    try:
        LOOT_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(LOOT_DIR, 0o700)
        return True
    except OSError:
        return False


def capture(data: bytes, *, ip: str, service: str, origin: str,
            filename: str = "",
            lineage: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Quarantine a captured payload. Returns its SHA-256, or None.

    `filename` is recorded as metadata only. It is attacker-controlled and is
    never used to build a path.

    `lineage` says which artifact named this one, at what depth, and from which
    line -- see intel/chain.py. It rides on the sighting rather than the sample
    because provenance belongs to an arrival, not to the bytes: the same ELF
    can be stage 2 of one dropper and stage 1 of another, and a per-sample
    field would have to pick one and be wrong about the rest. Optional and
    additive; sidecars written before it existed stay valid and readers that do
    not know the key are unaffected.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data[:MAX_FILE_BYTES])
    if len(data) < MIN_FILE_BYTES:
        return None
    if not _ensure_dir():
        return None

    digest = hashlib.sha256(data).hexdigest()
    blob = LOOT_DIR / f"{digest}.bin"
    meta_path = LOOT_DIR / f"{digest}.json"

    sighting = {
        "at": _now(),
        "ip": ip,
        "service": service,
        # How it arrived: sftp-put, shell-write, http-upload. Worth keeping --
        # the same binary via SFTP and via a `printf` heredoc are different
        # levels of attacker sophistication.
        "origin": origin,
        "filename": filename[:200],
    }
    if lineage:
        sighting["lineage"] = lineage

    with _lock:
        try:
            if not blob.exists():
                if _total_bytes() >= MAX_TOTAL_MB * 1024 * 1024:
                    return None
                # Written to a temp file in the same directory and renamed, so
                # the intel sidecar never sees a partial file and hashes it.
                handle, temp = tempfile.mkstemp(dir=str(LOOT_DIR), suffix=".part")
                try:
                    with os.fdopen(handle, "wb") as fh:
                        fh.write(data)
                    os.chmod(temp, 0o400)
                    os.replace(temp, blob)
                except OSError:
                    try:
                        os.unlink(temp)
                    except OSError:
                        pass
                    return None

            meta = _read_meta(digest) or {
                "sha256": digest,
                "size": len(data),
                "first_seen": sighting["at"],
                "sightings": [],
                "scan": None,
            }
            meta["last_seen"] = sighting["at"]
            # Bounded, keeping the most recent: one popular sample seen ten
            # thousand times must not grow a sidecar until it is the disk
            # problem the cap exists to prevent. Trimming from the front kept
            # the oldest 199 and discarded everything since, so a sample that
            # went quiet a month ago and came back today looked unchanged.
            meta["sightings"] = ((meta.get("sightings") or []) + [sighting])[-200:]
            meta["sighting_count"] = int(meta.get("sighting_count") or 0) + 1
            _write_meta(digest, meta)
        except OSError:
            return None

    return digest


def _read_meta(digest: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((LOOT_DIR / f"{digest}.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_meta(digest: str, meta: Dict[str, Any]) -> None:
    path = LOOT_DIR / f"{digest}.json"
    handle, temp = tempfile.mkstemp(dir=str(LOOT_DIR), suffix=".part")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, separators=(",", ":"))
        os.replace(temp, path)
    except Exception:
        # Otherwise a failed serialisation leaves a .part behind on every
        # attempt, and the loot directory slowly fills with them.
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def read_meta(digest: str) -> Optional[Dict[str, Any]]:
    """Public reader, for the dashboard and the intel sidecar."""
    if not _is_digest(digest):
        return None
    return _read_meta(digest)


def record_scan(digest: str, scan: Dict[str, Any]) -> bool:
    """Attach a scan verdict. Called by the intel sidecar, never by a honeypot."""
    if not _is_digest(digest):
        return False
    with _lock:
        meta = _read_meta(digest)
        if meta is None:
            return False
        meta["scan"] = scan
        try:
            _write_meta(digest, meta)
        except OSError:
            return False
    return True


def clear_scan(digest: str) -> bool:
    """Drop a recorded verdict so pending_scan() offers the sample again.

    The operator's re-scan, and the only kind worth having: a first scan already
    happens on its own within one VT_POLL_SECONDS. What moves is the verdict --
    a sample unknown to VirusTotal today is the interesting case precisely
    because it is often known a fortnight later, and nothing re-asks.

    Called by the intel sidecar, never by a honeypot and never by the dashboard,
    which mounts storage/ read-only and asks for this through a marker file.
    """
    if not _is_digest(digest):
        return False
    with _lock:
        meta = _read_meta(digest)
        if meta is None:
            return False
        if meta.get("scan") is None:
            # Already queued. Not a failure -- two clicks on the same row
            # should be one rescan, not an error.
            return True
        meta["scan"] = None
        try:
            _write_meta(digest, meta)
        except OSError:
            return False
    return True


def _is_digest(value: str) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def pending_scan():
    """Digests captured but not yet scanned, oldest first."""
    if not LOOT_DIR.is_dir():
        return []

    # stat() inside the sort key raced with a honeypot writing a new sidecar:
    # one missing file raised, and this runs in the intel container's only
    # loop, so a transient race became a crash and a restart.
    def mtime(path):
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    out = []
    try:
        files = sorted(LOOT_DIR.glob("*.json"), key=mtime)
    except OSError:
        return []
    for meta_file in files:
        digest = meta_file.stem
        if not _is_digest(digest):
            continue
        meta = _read_meta(digest)
        if meta and not meta.get("scan"):
            out.append(digest)
    return out
