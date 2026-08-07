#!/usr/bin/env python3
"""Retrieve second-stage payloads named in attacker commands.

OFF BY DEFAULT. This is the one component that deliberately connects *out* to
infrastructure an attacker chose, so every default here is the cautious one and
turning it on is a decision with consequences worth understanding:

  * Your address contacts theirs. A loader host that sees a fetch from a machine
    it just "infected" learns it found a honeypot. Some operators want that
    trade; nobody should make it by accident.
  * They control what you receive. Size, content and timing are theirs to pick,
    which is why every one of those is bounded below rather than trusted.
  * You end up storing live malware. Check your provider's acceptable-use
    policy first -- AUTHORIZATION.md 2.1 covers why that conversation is worth
    having before the samples arrive rather than after.

It runs in the intel container because that container already has egress and
already talks to VirusTotal. No honeypot gains a route out: they write IOCs to
the shared volume, this reads them, and the two never share a network.

Failsafes, in the order they fire:

    disabled by default          FETCH_ENABLED
    scheme allowlist             http/https only -- no file://, gopher://, ftp
    hostname resolved here       and re-checked, because the name is theirs
    public addresses only        every resolved A/AAAA must be routable
    no redirects                 a 302 to 169.254.169.254 is the attack
    connect + read timeouts      a hung socket must not pin a worker
    hard size cap                enforced while streaming, not from a header
    per-host cooldown            one host cannot be fetched in a loop
    global rate limit            bounded fetches per hour
    circuit breaker              repeated failure stops the attempt entirely
    storage cap                  loot.capture refuses past MAX_TOTAL_MB
    stored inert                 mode 0400, .bin suffix, never executed

RECURSION
    A stage-1 dropper's only job is to name the real payload once per CPU
    architecture. Fetching it and stopping meant the bot itself -- the artifact
    worth having -- was named in evidence we held and never collected. So a
    captured artifact that is text is parsed for further targets and those are
    fetched too, bounded by:

    depth limit                  FETCH_MAX_DEPTH levels of recursion, default 2
    artifacts per chain          FETCH_MAX_PER_CHAIN, default 16
    per-URL, per chain           a canonical URL is fetched at most once
    per-content, globally        loot.capture is content-addressed
    text only                    chain.is_text() -- an ELF is stored, never parsed

    Every per-fetch control above still applies to every child unchanged. One
    is deliberately relaxed: see _allowed_now() for why the per-host cooldown
    has to be, and exactly how far.
"""

import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, "/app")

import chain                                                   # noqa: E402
from shared import ioc, loot                                   # noqa: E402

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
IOC_DIR = Path(os.getenv("IOC_DIR", str(STORAGE_DIR / "ioc")))

ENABLED = os.getenv("FETCH_ENABLED", "false").strip().lower() in ("1", "true", "yes")
POLL_SECONDS = max(int(os.getenv("FETCH_POLL_SECONDS", "60")), 15)
CONNECT_TIMEOUT = float(os.getenv("FETCH_TIMEOUT", "8"))
MAX_BYTES = int(os.getenv("FETCH_MAX_BYTES", str(8 * 1024 * 1024)))
MAX_PER_HOUR = int(os.getenv("FETCH_MAX_PER_HOUR", "20"))
HOST_COOLDOWN = int(os.getenv("FETCH_HOST_COOLDOWN", "3600"))
RETRY_AFTER = int(os.getenv("FETCH_RETRY_AFTER", "86400"))
BREAKER_TRIP = int(os.getenv("FETCH_BREAKER_FAILURES", "10"))
BREAKER_RESET = int(os.getenv("FETCH_BREAKER_RESET", "1800"))

# Levels of recursion, not artifacts. 0 restores the original behaviour
# exactly: fetch what the attacker named and stop. 1 is what closes the gap --
# the command names wget.sh, wget.sh names the architecture binaries, and that
# is the whole of this family's chain. 2 is the default because it costs
# nothing when there is no third level (a chain ends at the first binary
# regardless) and covers the loaders that stage through an intermediate.
MAX_DEPTH = int(os.getenv("FETCH_MAX_DEPTH", "2"))

# Total artifacts one chain may retrieve, root included. A multi-architecture
# dropper names 11 to 13, so this clears a real one with room and still bounds
# a hostile script that names ten thousand.
MAX_PER_CHAIN = int(os.getenv("FETCH_MAX_PER_CHAIN", "16"))

ALLOWED_SCHEMES = {"http", "https"}
CHUNK = 64 * 1024

_recent: list = []                  # fetch timestamps, for the hourly ceiling
_host_seen: Dict[str, float] = {}
_breaker = {"failures": 0, "open_until": 0.0}


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] fetcher: {message}", flush=True)


def _public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_reserved
                or parsed.is_link_local or parsed.is_multicast
                or parsed.is_unspecified)


def resolve_public(host: str, port: int) -> Optional[str]:
    """Resolve, and refuse unless EVERY answer is publicly routable.

    Every answer, not the first: a hostname that returns one public address and
    one at 169.254.169.254 is not a mistake, it is the cloud-metadata attack,
    and connecting to the good one first does not make the record safe. The
    honeypot recorded a name it could not resolve -- resolution happens here,
    where it is about to matter.
    """
    try:
        answers = socket.getaddrinfo(host.strip("[]"), port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not answers:
        return None
    addresses = {entry[4][0] for entry in answers}
    if not all(_public(address) for address in addresses):
        return None
    return sorted(addresses)[0]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects are refused rather than followed.

    The target is attacker-controlled, so a 302 is an invitation to somewhere
    the address checks above already rejected. Declining is the whole point.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, f"redirect refused: {newurl}",
                                     headers, fp)


def _allowed_now(host: str, chain_hosts: Optional[set] = None) -> Optional[str]:
    """None when a fetch may proceed, otherwise the reason it may not.

    `chain_hosts` are hosts already fetched from inside the chain now running.
    They skip the per-host cooldown, and only that.

    This exemption is necessary rather than convenient. A dropper and the
    binaries it names are on the same host -- that is what a dropper is. With
    the cooldown applied uniformly, recursion fetches wget.sh, parses out
    eleven architecture URLs, and refuses all eleven with "host cooling down
    (3599s left)". The chain then dribbles out one architecture per hour
    against infrastructure that is up for days, which is a feature that
    technically works and practically does not.

    What it does not exempt, deliberately:

      * the circuit breaker -- a host failing repeatedly stops the chain
      * the hourly ceiling -- total outbound volume is unchanged, so a chain
        can be cut short by it, and the remaining targets stay recorded as
        IOCs for the next pass rather than being lost
      * MAX_PER_CHAIN -- the exemption is bounded by the chain budget, so the
        worst case against one host is one burst of that many requests
      * starting a *new* chain against a host in cooldown, which is still
        refused -- the loop this control exists to prevent
    """
    now = time.time()
    if _breaker["open_until"] > now:
        return "circuit breaker open"
    global _recent
    _recent = [stamp for stamp in _recent if now - stamp < 3600]
    if len(_recent) >= MAX_PER_HOUR:
        return f"hourly ceiling of {MAX_PER_HOUR} reached"
    if chain_hosts and host in chain_hosts:
        return None
    last = _host_seen.get(host)
    if last and now - last < HOST_COOLDOWN:
        return f"host cooling down ({int(HOST_COOLDOWN - (now - last))}s left)"
    return None


def _note_failure() -> None:
    _breaker["failures"] += 1
    if _breaker["failures"] >= BREAKER_TRIP:
        _breaker["open_until"] = time.time() + BREAKER_RESET
        _breaker["failures"] = 0
        log(f"breaker tripped; no fetches for {BREAKER_RESET}s")


def fetch(url: str, address: str) -> Tuple[Optional[bytes], str]:
    """Body, or (None, reason). Size is enforced while reading."""
    request = urllib.request.Request(url, method="GET", headers={
        # Honest about being automated. Pretending to be a browser to a malware
        # host buys nothing and makes the traffic harder to explain later.
        "User-Agent": "Mozilla/5.0 (compatible; drosera-collector/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    })
    opener = urllib.request.build_opener(_NoRedirects)
    try:
        with opener.open(request, timeout=CONNECT_TIMEOUT) as response:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > MAX_BYTES:
                return None, f"declared {declared}B over cap"
            body = b""
            while len(body) <= MAX_BYTES:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                body += chunk
            # Checked after reading, so a lying Content-Length changes nothing.
            if len(body) > MAX_BYTES:
                return None, f"body over {MAX_BYTES}B cap"
            if not body:
                return None, "empty body"
            return body, f"{len(body)}B from {address}"
    except urllib.error.HTTPError as exc:
        return None, f"http {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _url_of(entry: Dict[str, Any]) -> str:
    return (f"{str(entry.get('scheme') or '').lower()}://{entry.get('host')}"
            f":{int(entry.get('port') or 80)}{entry.get('path') or '/'}")


def _write_fetch(path: Path, entry: Dict[str, Any], status: str, detail: str,
                 digest: Optional[str] = None,
                 derived: Optional[int] = None) -> None:
    """Record the outcome on an IOC sidecar. Additive; nothing existing moves.

    The record on disk is the base, not the entry in hand. A child target is a
    bare ioc.extract() dict -- scheme, host, port, path, method, raw, public --
    and _derive() has already persisted the full record with its sightings,
    times_seen, first_seen and lineage. Writing the in-hand dict back would
    overwrite all of that with the seven fields it happens to carry, so the
    provenance this feature exists to record would be destroyed by the very
    next line that recorded the fetch succeeding.
    """
    base: Dict[str, Any] = {}
    try:
        base = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        base = {}
    if not isinstance(base, dict) or not base:
        base = dict(entry)

    record = {"status": status, "detail": detail[:300], "sha256": digest,
              "at": datetime.now(timezone.utc).isoformat()}
    if derived is not None:
        # How many further targets this artifact named. Distinguishes "parsed,
        # named nothing" from "never parsed", which otherwise look identical
        # and send you looking for a bug in the parser that is not there.
        record["derived"] = int(derived)
    base["fetch"] = record

    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(base, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _attempt(entry: Dict[str, Any],
             chain_hosts: set) -> Tuple[Optional[bytes], str, str]:
    """One fetch, with every control applied. (body, detail, status).

    Status is one of captured / skipped / blocked / refused / failed. `blocked`
    is the only transient one -- it means a limit said not now, so the target
    keeps its previous state and is tried again on a later pass.
    """
    scheme = str(entry.get("scheme") or "").lower()
    host = str(entry.get("host") or "")
    port = int(entry.get("port") or 80)

    # tftp and ftp are recorded but never retrieved: both would mean writing a
    # client for a protocol whose only user here is malware, for a marginal
    # gain over the http copy the same loader almost always offers.
    if scheme not in ALLOWED_SCHEMES:
        return None, f"scheme {scheme} not fetched", "skipped"
    if not host:
        return None, "no host", "skipped"

    blocked = _allowed_now(host, chain_hosts)
    if blocked:
        return None, blocked, "blocked"

    address = resolve_public(host, port)
    if address is None:
        return None, "does not resolve to a publicly routable address", "refused"

    _recent.append(time.time())
    _host_seen[host] = time.time()
    body, detail = fetch(_url_of(entry), address)
    if body is None:
        _note_failure()
        return None, detail, "failed"

    _breaker["failures"] = 0
    return body, detail, "captured"


def _derive(body: bytes, *, parent_digest: str, depth: int,
            ip: str, service: str) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Targets named inside a captured artifact, persisted as IOCs.

    Returns (entry, lineage) pairs. Persisting here rather than only enqueuing
    them means a chain cut short by the hourly ceiling has still recorded what
    it found: the remaining architectures appear on the dashboard's loader list
    and are picked up on a later pass instead of being discovered and dropped.
    """
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    try:
        children = chain.extract_from_body(body)
    except Exception as exc:                                    # noqa: BLE001
        log(f"parse failed at depth {depth}: {exc}")
        return out

    for child in children:
        lineage = chain.lineage(parent_sha256=parent_digest, depth=depth,
                                source_line=child.get("source_line") or "",
                                method=str(child.get("method") or ""))
        try:
            ioc.record_derived([child], ip=ip, service=service, lineage=lineage)
        except Exception:                                       # noqa: BLE001
            # Recording is a bonus; failing to write a sidecar must not stop
            # us fetching the thing it describes.
            pass
        out.append((child, lineage))
    return out


def run_chain(root: Dict[str, Any], root_path: Path) -> None:
    """Fetch this target, then whatever it names, to a bounded depth."""
    sighting = (root.get("sightings") or [{}])[-1]
    ip = str(sighting.get("ip") or "unknown")
    service = str(sighting.get("service") or "fetch")

    visited = {chain.canonical(root)}
    chain_hosts: set = set()
    fetched = 0

    # (entry, sidecar path, depth, lineage). The root has no lineage: nothing
    # named it but the attacker, and that is already in its sightings.
    queue: List[Tuple[Dict[str, Any], Optional[Path], int, Optional[Dict]]] = [
        (root, root_path, 0, None)]

    while queue:
        entry, path, depth, lineage = queue.pop(0)
        url = _url_of(entry)

        if fetched >= MAX_PER_CHAIN:
            log(f"chain budget of {MAX_PER_CHAIN} spent; {len(queue) + 1} "
                f"target(s) left recorded for a later pass")
            return

        # One target failing must not abandon the rest of the chain, and must
        # not escape into the poll loop -- main() catches, but a raise there
        # abandons every other IOC file in the pass. fetch() already turns
        # transport errors into a status; this is for everything that is not
        # supposed to be able to happen, which is the category that does.
        try:
            body, detail, status = _attempt(entry, chain_hosts)
        except Exception as exc:                                # noqa: BLE001
            _note_failure()
            body, detail, status = None, f"{type(exc).__name__}: {exc}", "failed"

        if status == "blocked":
            # Transient. Leave the sidecar alone so the existing retry logic
            # sees it as untried rather than failed.
            if depth == 0:
                return
            log(f"deferred {url}: {detail}")
            continue

        if status != "captured":
            if path is not None:
                _write_fetch(path, entry, status, detail)
            log(f"{status} {url}: {detail}")
            continue

        fetched += 1
        chain_hosts.add(str(entry.get("host") or ""))

        digest = loot.capture(
            body,
            ip=ip, service=service,
            # Unchanged for children too: the depth is in the lineage, and a
            # new origin value would quietly fall out of every existing filter
            # that matches on this one.
            origin="loader-fetch",
            filename=str(entry.get("path") or "")[:200],
            lineage=lineage,
        )
        if not digest:
            if path is not None:
                _write_fetch(path, entry, "rejected",
                             "quarantine declined it (size or storage cap)")
            continue

        # An ELF is the prize and is stored like anything else. It is simply
        # never handed to a parser -- chain.is_text() decides, not the depth.
        children: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        if depth < MAX_DEPTH and chain.is_text(body):
            children = _derive(body, parent_digest=digest, depth=depth + 1,
                               ip=ip, service=service)

        if path is not None:
            _write_fetch(path, entry, "captured", detail, digest,
                         derived=len(children) if depth < MAX_DEPTH else None)
        log(f"captured {url} -> {digest[:16]} ({detail})"
            + (f", named {len(children)}" if children else ""))

        for child, child_lineage in children:
            key = chain.canonical(child)
            if key in visited:
                continue                # never the same URL twice in one chain
            visited.add(key)
            queue.append((child, IOC_DIR / f"{ioc.key_for(child)}.json",
                          depth + 1, child_lineage))


def backfill(entry: Dict[str, Any], path: Path) -> bool:
    """Parse an artifact captured before recursion existed. No network.

    Without this the feature only helps the next attack, and the dropper
    already sitting in the quarantine -- the reason any of this was written --
    stays a dead end. Reads the stored blob, derives targets, and records them;
    they are fetched on the next pass like any other IOC.
    """
    previous = entry.get("fetch") or {}
    digest = previous.get("sha256")
    if not digest or previous.get("derived") is not None:
        return False
    try:
        body = (loot.LOOT_DIR / f"{digest}.bin").read_bytes()
    except OSError:
        return False
    if not chain.is_text(body):
        _write_fetch(path, entry, "captured", str(previous.get("detail") or ""),
                     digest, derived=0)
        return False

    sighting = (entry.get("sightings") or [{}])[-1]
    children = _derive(body, parent_digest=digest, depth=1,
                       ip=str(sighting.get("ip") or "unknown"),
                       service=str(sighting.get("service") or "fetch"))
    _write_fetch(path, entry, "captured", str(previous.get("detail") or ""),
                 digest, derived=len(children))
    if children:
        log(f"backfilled {_url_of(entry)} -> named {len(children)} target(s)")
    return bool(children)


def process(path: Path) -> None:
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    previous = entry.get("fetch") or {}
    if previous.get("status") == "captured":
        if MAX_DEPTH > 0:
            backfill(entry, path)
        return
    tried = previous.get("at")
    if tried:
        try:
            age = time.time() - datetime.fromisoformat(tried).timestamp()
            if age < RETRY_AFTER:
                return
        except ValueError:
            pass

    run_chain(entry, path)


def main() -> None:
    if not ENABLED:
        log("disabled (FETCH_ENABLED is not true); exiting")
        return
    log(f"enabled: <={MAX_BYTES}B, <={MAX_PER_HOUR}/h, "
        f"{HOST_COOLDOWN}s per-host cooldown, redirects refused")
    log(f"recursion: depth {MAX_DEPTH}, <={MAX_PER_CHAIN} artifacts per chain"
        if MAX_DEPTH > 0 else "recursion: off (FETCH_MAX_DEPTH=0)")
    if MAX_DEPTH > 0 and MAX_PER_HOUR < MAX_PER_CHAIN * 2:
        # Said once, at startup, because the failure is silent otherwise: the
        # chain simply stops partway and the remaining architectures sit as
        # unfetched IOCs looking like a parser problem.
        log(f"note: FETCH_MAX_PER_HOUR={MAX_PER_HOUR} is below two full chains "
            f"({MAX_PER_CHAIN} each); chains may be truncated by the ceiling")
    while True:
        try:
            if IOC_DIR.is_dir():
                for path in sorted(IOC_DIR.glob("*.json")):
                    process(path)
        except Exception as exc:                                # noqa: BLE001
            log(f"pass failed: {exc}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
