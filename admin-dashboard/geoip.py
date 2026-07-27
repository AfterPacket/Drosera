"""GeoIP lookups for the operator dashboard.

Optional by design. The database is a licensed MaxMind file that cannot be
redistributed with this repo, and the appliance has to work without it, so
every function here degrades to None rather than raising.

Two sources, in order of quality:

  1. A MaxMind GeoLite2-City database at GEOIP_DB. Covers every protocol,
     because it works from the address alone.
  2. Cloudflare's CF-IPCountry header, recorded on web events. Country only,
     and only for traffic that came through the proxy -- which is to say, not
     SSH, telnet, SMB, RDP or anything else on the raw IP.

Without (1) the map is empty for everything except web hits, which is why the
Country column reads "—" on a fresh install.
"""

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

GEOIP_DB = Path(os.getenv("GEOIP_DB", "/geoip/GeoLite2-City.mmdb"))

_reader = None
_reader_tried = False
_lock = threading.Lock()

# Bounded so a scan flood cannot grow it without limit; lookups are cheap
# enough that a modest cache is only there to spare the mmap on hot IPs.
_cache: Dict[str, Optional[Dict[str, Any]]] = {}
_CACHE_MAX = 4096


def available() -> bool:
    return _open() is not None


def _open():
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    with _lock:
        if _reader_tried:
            return _reader
        _reader_tried = True
        if not GEOIP_DB.is_file():
            return None
        try:
            import maxminddb
            _reader = maxminddb.open_database(str(GEOIP_DB))
        except Exception:                                   # noqa: BLE001
            _reader = None
    return _reader


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Return {country, country_code, city, lat, lon} or None."""
    if not ip:
        return None
    if ip in _cache:
        return _cache[ip]

    reader = _open()
    result: Optional[Dict[str, Any]] = None
    if reader is not None:
        try:
            record = reader.get(ip) or {}
            country = record.get("country") or record.get("registered_country") or {}
            city = record.get("city") or {}
            location = record.get("location") or {}
            names = country.get("names") or {}
            city_names = city.get("names") or {}
            if country.get("iso_code") or location.get("latitude") is not None:
                result = {
                    "country": names.get("en"),
                    "country_code": country.get("iso_code"),
                    "city": city_names.get("en"),
                    "lat": location.get("latitude"),
                    "lon": location.get("longitude"),
                }
        except Exception:                                   # noqa: BLE001
            result = None

    if len(_cache) >= _CACHE_MAX:
        _cache.clear()
    _cache[ip] = result
    return result


def describe(ip: str, fallback_country_code: Optional[str] = None) -> Optional[str]:
    """One-line human form: 'Amsterdam, Netherlands' or just 'NL'."""
    record = lookup(ip)
    if record:
        parts = [record.get("city"), record.get("country")]
        joined = ", ".join(part for part in parts if part)
        if joined:
            return joined
        if record.get("country_code"):
            return record["country_code"]
    if fallback_country_code and fallback_country_code != "XX":
        return fallback_country_code
    return None


def country_code(ip: str, fallback: Optional[str] = None) -> Optional[str]:
    record = lookup(ip)
    if record and record.get("country_code"):
        return record["country_code"]
    return fallback if fallback and fallback != "XX" else None
