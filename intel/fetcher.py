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
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, "/app")

from shared import loot                                        # noqa: E402

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


def _allowed_now(host: str) -> Optional[str]:
    """None when a fetch may proceed, otherwise the reason it may not."""
    now = time.time()
    if _breaker["open_until"] > now:
        return "circuit breaker open"
    global _recent
    _recent = [stamp for stamp in _recent if now - stamp < 3600]
    if len(_recent) >= MAX_PER_HOUR:
        return f"hourly ceiling of {MAX_PER_HOUR} reached"
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


def process(path: Path) -> None:
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    previous = entry.get("fetch") or {}
    if previous.get("status") == "captured":
        return
    tried = previous.get("at")
    if tried:
        try:
            age = time.time() - datetime.fromisoformat(tried).timestamp()
            if age < RETRY_AFTER:
                return
        except ValueError:
            pass

    scheme = str(entry.get("scheme") or "").lower()
    host = str(entry.get("host") or "")
    port = int(entry.get("port") or 80)
    url = f"{scheme}://{host}:{port}{entry.get('path') or '/'}"

    def finish(status: str, detail: str, digest: Optional[str] = None) -> None:
        entry["fetch"] = {"status": status, "detail": detail[:300],
                          "sha256": digest, "at": datetime.now(timezone.utc).isoformat()}
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(entry, default=str), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    # tftp and ftp are recorded but never retrieved: both would mean writing a
    # client for a protocol whose only user here is malware, for a marginal
    # gain over the http copy the same loader almost always offers.
    if scheme not in ALLOWED_SCHEMES:
        finish("skipped", f"scheme {scheme} not fetched")
        return

    blocked = _allowed_now(host)
    if blocked:
        return                      # transient; try again next pass

    address = resolve_public(host, port)
    if address is None:
        finish("refused", "does not resolve to a publicly routable address")
        log(f"refused {url}: non-public or unresolvable")
        return

    _recent.append(time.time())
    _host_seen[host] = time.time()
    body, detail = fetch(url, address)
    if body is None:
        _note_failure()
        finish("failed", detail)
        log(f"failed {url}: {detail}")
        return

    _breaker["failures"] = 0
    sighting = (entry.get("sightings") or [{}])[-1]
    digest = loot.capture(
        body,
        ip=str(sighting.get("ip") or "unknown"),
        service=str(sighting.get("service") or "fetch"),
        origin="loader-fetch",
        filename=str(entry.get("path") or "")[:200],
    )
    if digest:
        finish("captured", detail, digest)
        log(f"captured {url} -> {digest[:16]} ({detail})")
    else:
        finish("rejected", "quarantine declined it (size or storage cap)")


def main() -> None:
    if not ENABLED:
        log("disabled (FETCH_ENABLED is not true); exiting")
        return
    log(f"enabled: <={MAX_BYTES}B, <={MAX_PER_HOUR}/h, "
        f"{HOST_COOLDOWN}s per-host cooldown, redirects refused")
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
