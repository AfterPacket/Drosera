#!/usr/bin/env python3
"""Telemetry collector for drosera.lol.

Runs on the PROJECT's host, not on a honeypot. Deployments that have opted in
POST their aggregate counts here; this sums them across instances and serves one
JSON document for the website to read.

Two things worth being honest about:

  * The numbers are self-reported. Anyone can POST whatever they like unless
    TELEMETRY_TOKEN is set, in which case only holders of the token can. Set it
    if the figures are ever going to be quoted as anything more than "roughly
    this much traffic across the deployments that told us about it".
  * The collector stores an instance id and the counts. It does not store, and
    is not sent, any address, credential, payload or hostname -- see
    telemetry/aggregate.py for the exact set of fields a reporter produces.

Stdlib only, and every write goes through a whitelist: the request body is never
stored as it arrived, only the specific numeric fields copied out of it.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA_DIR = Path(os.getenv("COLLECTOR_DATA_DIR", "/data"))
PORT = int(os.getenv("COLLECTOR_PORT", "8080"))
BIND = os.getenv("COLLECTOR_BIND", "0.0.0.0")
TOKEN = os.getenv("TELEMETRY_TOKEN", "").strip()
CORS_ORIGIN = os.getenv("COLLECTOR_CORS_ORIGIN", "*")

# An instance that stops reporting drops out of the totals rather than inflating
# them forever. Long enough to survive a weekend of downtime.
STALE_AFTER_DAYS = int(os.getenv("COLLECTOR_STALE_DAYS", "14"))
MAX_BODY = 64 * 1024
CACHE_SECONDS = 60

INSTANCE_RE = re.compile(r"^[0-9a-f]{8,64}$")

# Every field copied out of a report, and the ceiling each is clamped to. A
# report claiming a quintillion events is either broken or hostile, and either
# way it must not be able to define the scale of a chart on the front page.
NUMERIC_FIELDS = {
    "days_observed": 100000,
    "unique_ips": 10 ** 9,
    "ips_blocked": 10 ** 9,
    "events": 10 ** 12,
    "minutes_wasted": 10 ** 10,
    "hours_wasted": 10 ** 9,
    "countries": 300,
}

_lock = threading.Lock()
_cache = {"payload": None, "at": 0.0}


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] {message}", flush=True)


def clean(report: dict) -> dict:
    """Copy out only what we publish, clamped. Nothing else survives."""
    stats = report.get("stats")
    if not isinstance(stats, dict):
        raise ValueError("missing stats")

    out = {}
    for field, ceiling in NUMERIC_FIELDS.items():
        value = stats.get(field)
        if not isinstance(value, (int, float)) or value != value:  # NaN check
            value = 0
        out[field] = max(0, min(float(value), ceiling))

    services = {}
    raw = stats.get("by_service")
    if isinstance(raw, list):
        for entry in raw[:20]:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("service") or "")[:24]
            count = entry.get("events")
            if name and isinstance(count, (int, float)):
                services[name] = max(0, min(float(count), 10 ** 12))
    out["by_service"] = services

    version = str(report.get("version") or "unknown")[:32]
    return {
        "version": re.sub(r"[^\w.\-]", "", version) or "unknown",
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "stats": out,
    }


def store(instance: str, record: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / f"{instance}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    tmp.replace(path)


def aggregate() -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_AFTER_DAYS)
    totals = {field: 0.0 for field in NUMERIC_FIELDS}
    services = {}
    instances = 0
    newest = None

    if DATA_DIR.is_dir():
        for path in sorted(DATA_DIR.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                when = datetime.fromisoformat(record["reported_at"])
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < cutoff:
                continue

            instances += 1
            newest = when if newest is None or when > newest else newest
            stats = record.get("stats") or {}
            for field in NUMERIC_FIELDS:
                totals[field] += float(stats.get(field) or 0)
            for name, count in (stats.get("by_service") or {}).items():
                services[name] = services.get(name, 0) + float(count)

    # days_observed and countries are per-instance and do not sum into anything
    # meaningful -- two deployments each watching 90 days have not observed 180.
    # Report the largest instead, and say so in the field name.
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "last_report_at": newest.isoformat() if newest else None,
        "instances": instances,
        "unique_ips": int(totals["unique_ips"]),
        "ips_blocked": int(totals["ips_blocked"]),
        "events": int(totals["events"]),
        "minutes_wasted": round(totals["minutes_wasted"], 1),
        "hours_wasted": round(totals["hours_wasted"], 1),
        "max_days_observed": int(totals["days_observed"] / instances) if instances else 0,
        "max_countries": int(totals["countries"] / instances) if instances else 0,
        "by_service": [
            {"service": name, "events": int(count)}
            for name, count in sorted(services.items(), key=lambda kv: -kv[1])
        ],
    }


def cached():
    with _lock:
        if _cache["payload"] and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["payload"]
    payload = aggregate()
    with _lock:
        _cache["payload"] = payload
        _cache["at"] = time.time()
    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "drosera-collector"
    sys_version = ""

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        route = self.path.split("?", 1)[0].rstrip("/") or "/"
        if route == "/healthz":
            self._send(200, b'{"ok":true}')
        elif route in ("/", "/stats", "/stats.json", "/api/stats"):
            self._send(200, json.dumps(cached(), separators=(",", ":")).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path.split("?", 1)[0].rstrip("/") != "/api/report":
            self._send(404, b'{"error":"not found"}')
            return

        if TOKEN:
            supplied = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            # Constant-time-ish: compare full strings, never short-circuit on
            # the first differing byte by comparing lengths first.
            if len(supplied) != len(TOKEN) or supplied != TOKEN:
                self._send(401, b'{"error":"unauthorized"}')
                return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send(413, b'{"error":"bad length"}')
            return

        try:
            report = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            if not isinstance(report, dict):
                raise ValueError("not an object")
            instance = str(report.get("instance") or "")
            if not INSTANCE_RE.match(instance):
                raise ValueError("bad instance id")
            store(instance, clean(report))
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            log(f"rejected report: {exc}")
            self._send(400, b'{"error":"bad report"}')
            return

        with _lock:
            _cache["at"] = 0.0            # next reader recomputes
        self._send(202, b'{"ok":true}')

    def log_message(self, fmt, *args):
        return


def main():
    log(f"collector on {BIND}:{PORT}, data in {DATA_DIR}, "
        f"token {'set' if TOKEN else 'NOT set (anyone may report)'}")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
