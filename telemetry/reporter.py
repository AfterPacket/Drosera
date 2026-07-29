#!/usr/bin/env python3
"""Opt-in aggregate reporting to the Drosera project collector.

OFF BY DEFAULT, and it stays off unless an operator sets TELEMETRY_ENABLED=true
and starts the profile. That is not a formality. This project's entire pitch is
that no honeypot container can reach the internet, and people deploy it
precisely because they want a box that does not talk to anyone. A security
appliance that phoned home by default would be trading exactly the property it
was chosen for.

What leaves the box when it IS enabled:

    instance id      random, generated once, stored locally. Not derived from
                     the hostname, the address, or anything else about the
                     machine, so it cannot be worked backwards into an identity
    counts           unique addresses seen, addresses blocked, events, minutes
                     wasted, number of source countries, per-service event
                     totals
    version + uptime days of log retained

What never leaves, because it is never read into this process:

    addresses, credentials, payloads, recordings, commands, loot, hostnames,
    the operator's identity, the allowed-IP list, anything from .env

The collector cannot ask for more than that either -- this is a one-way POST to
a fixed URL, and nothing here reads a response beyond its status code.
"""

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/app")

from aggregate import build_aggregate                          # noqa: E402

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
STATE_FILE = STORAGE_DIR / "telemetry-instance.json"

ENABLED = os.getenv("TELEMETRY_ENABLED", "false").strip().lower() in ("1", "true", "yes")
COLLECTOR = os.getenv("TELEMETRY_URL", "https://drosera.lol/api/report").strip()
TOKEN = os.getenv("TELEMETRY_TOKEN", "").strip()
LABEL = os.getenv("TELEMETRY_LABEL", "").strip()[:40]
INTERVAL = max(int(os.getenv("TELEMETRY_INTERVAL", "3600")), 900)
TIMEOUT = float(os.getenv("TELEMETRY_TIMEOUT", "15"))
VERSION = os.getenv("DROSERA_VERSION", "unknown")[:32]


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] {message}", flush=True)


def instance_id() -> str:
    """A random identifier, generated once and kept.

    Random rather than derived. A hash of the hostname or the public address
    would be stable without needing storage, but it would also be reversible by
    anyone holding a candidate list -- which for IPv4 is everyone. This is only
    here so a redeploy does not double-count one participant.
    """
    try:
        if STATE_FILE.is_file():
            saved = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if saved.get("id"):
                return str(saved["id"])[:64]
    except (OSError, json.JSONDecodeError):
        pass

    generated = secrets.token_hex(16)
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "id": generated,
            "created": datetime.now(timezone.utc).isoformat(),
        }), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError:
        # Unwritable storage means a new id each restart. Over-counting
        # instances is a far better failure than refusing to start.
        log("could not persist instance id; using an ephemeral one")
    return generated


def report(payload: dict) -> bool:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        COLLECTOR, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"drosera-telemetry/{VERSION}",
        },
    )
    if TOKEN:
        request.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"report failed: {exc}")
        return False


def main() -> None:
    if not ENABLED:
        log("telemetry disabled (TELEMETRY_ENABLED is not true); exiting")
        return
    if not COLLECTOR.startswith("https://"):
        # Refused rather than downgraded. This crosses the public internet and
        # an operator who mistypes the scheme should be told, not silently
        # given a plaintext channel.
        log(f"refusing to report to a non-HTTPS collector: {COLLECTOR!r}")
        return

    ident = instance_id()
    log(f"telemetry enabled -> {COLLECTOR} every {INTERVAL}s as {ident[:8]}...")

    while True:
        try:
            stats = build_aggregate(STORAGE_DIR)
            payload = {
                "schema": 1,
                "instance": ident,
                "version": VERSION,
                "reported_at": datetime.now(timezone.utc).isoformat(),
                "stats": stats,
            }
            if LABEL:
                payload["label"] = LABEL
            if report(payload):
                log(f"reported {stats['events']} events, "
                    f"{stats['unique_ips']} addresses, "
                    f"{stats['ips_blocked']} blocked")
        except Exception as exc:                                # noqa: BLE001
            # Never die. A reporting problem must not become an operational one.
            log(f"cycle failed: {exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
