"""Fold a storage tree into the handful of counts telemetry is allowed to send.

Separated from the reporter so the set of fields that can leave the box is one
short function that can be read end to end. Everything it returns is a count.
There is no branch here that can emit an address, a credential or a payload,
because none of those is ever bound to a name that reaches the return value.

Stdlib only: the one component that talks to the internet should not carry a
dependency tree.
"""

import gzip
import json
import re
from pathlib import Path

DAY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl")

# Bounds the memory a very long retention can cost. Only ever used to size a
# distinct count; the set itself never leaves this module.
MAX_TRACKED_IPS = 400000

SERVICE_LABELS = {
    "ssh": "SSH", "telnet": "Telnet", "ftp": "FTP", "smtp": "SMTP",
    "mysql": "MySQL", "smb": "SMB", "rdp": "RDP", "web": "Web",
}


def _day_files(log_dir: Path, day: str):
    live = log_dir / f"{day}.jsonl"
    rotated = sorted(p for p in log_dir.glob(f"{day}.jsonl.*") if p.is_file())
    return ([live] if live.is_file() else []) + rotated


def _available_days(log_dir: Path):
    if not log_dir.is_dir():
        return []
    days = set()
    for path in log_dir.glob("*.jsonl*"):
        match = DAY_RE.match(path.name)
        if match:
            days.add(match.group(1))
    return sorted(days, reverse=True)


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def build_aggregate(storage_dir: Path, max_days: int = 400) -> dict:
    log_dir = Path(storage_dir) / "logs"
    days = _available_days(log_dir)[:max_days]

    addresses = set()
    blocked = set()
    countries = set()
    services = {}
    events = 0
    tarpit_seconds = 0.0

    for day in days:
        for path in _day_files(log_dir, day):
            try:
                with _open(path) as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(record, dict):
                            continue

                        events += 1
                        address = record.get("real_ip")
                        if address and len(addresses) < MAX_TRACKED_IPS:
                            addresses.add(address)

                        kind = record.get("event_type")
                        if kind == "BAN" and address:
                            blocked.add(address)
                        elif kind == "TARPIT_HELD":
                            tarpit_seconds += float(record.get("held_seconds") or 0)

                        service = record.get("service")
                        if service:
                            services[service] = services.get(service, 0) + 1

                        # Country code only, and only where the honeypot already
                        # recorded one. No GeoIP database is opened here.
                        code = (record.get("headers") or {}).get("cf_ipcountry")
                        if code and code != "XX":
                            countries.add(code)
            except (OSError, EOFError, gzip.BadGzipFile):
                continue

    return {
        "days_observed": len(days),
        "first_day": days[-1] if days else None,
        "last_day": days[0] if days else None,
        "unique_ips": len(addresses),
        "ips_blocked": len(blocked),
        "events": events,
        "minutes_wasted": round(tarpit_seconds / 60, 1),
        "hours_wasted": round(tarpit_seconds / 3600, 1),
        "countries": len(countries),
        "by_service": [
            {"service": name, "label": SERVICE_LABELS.get(name, name), "events": count}
            for name, count in sorted(services.items(), key=lambda kv: -kv[1])
        ],
    }
