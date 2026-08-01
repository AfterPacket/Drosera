#!/usr/bin/env python3
"""Ships Drosera events into Elasticsearch and provisions the index side.

Same shape as session-cam: it reads the JSONL event log off the shared storage
volume -- a filesystem handoff, not a network one -- and talks only to
Elasticsearch. It is on elastic-internal and honeypot-internal is not one of its
networks, so the search stack can never be reached from the honeypot side.

Filebeat would do the tailing, but it wants a writable registry directory and a
config file with specific ownership, both of which fight a read-only rootfs and
a non-root user. This is ~1 file of stdlib instead, and it fails in ways we
control.

Offsets are checkpointed per file and only advanced after Elasticsearch has
acknowledged the batch, so a crash re-sends rather than loses. Document IDs are
derived from (file, offset), which makes a re-send idempotent instead of a
duplicate.
"""

import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
LOG_DIR = STORAGE_DIR / "logs"
STATE_FILE = STORAGE_DIR / ".elastic-shipper.json"

ES_URL = os.getenv("ELASTIC_URL", "http://elasticsearch:9200").rstrip("/")
ES_USER = os.getenv("ELASTIC_USERNAME", "elastic")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
KIBANA_URL = os.getenv("KIBANA_URL", "http://kibana:5601").rstrip("/")
KIBANA_PASSWORD = os.getenv("KIBANA_PASSWORD", "")

# Names this deployment when several ship into one Elasticsearch. Empty for a
# single instance, where every document would carry the same value and the
# field would only cost storage.
INSTANCE = os.getenv("DROSERA_INSTANCE", "").strip()

INDEX_PREFIX = os.getenv("ELASTIC_INDEX_PREFIX", "drosera")
ILM_POLICY = f"{INDEX_PREFIX}-retention"
PIPELINE = f"{INDEX_PREFIX}-events"
RETENTION_DAYS = int(os.getenv("ELASTIC_RETENTION_DAYS", "90"))

# Thresholds for deciding the index was reset underneath us. A checkpoint
# claiming less than this has shipped almost nothing anyway, so re-reading it
# costs nothing and proves nothing; an index holding more than this is clearly
# alive and should not be re-sent over.
RESET_MIN_BYTES = int(os.getenv("ELASTIC_RESET_MIN_BYTES", "65536"))
RESET_MAX_DOCS = int(os.getenv("ELASTIC_RESET_MAX_DOCS", "100"))

POLL_SECONDS = int(os.getenv("ELASTIC_POLL_SECONDS", "15"))
BATCH_LINES = int(os.getenv("ELASTIC_BATCH_LINES", "500"))
MAX_LINE_BYTES = 256 * 1024
TIMEOUT = float(os.getenv("ELASTIC_TIMEOUT_SECONDS", "30"))

GEOIP_DB = Path(os.getenv("GEOIP_DB", "/geoip/GeoLite2-City.mmdb"))

_geoip_reader = None


def log(message: str) -> None:
    print(f"[elastic] {message}", flush=True)


# ------------------------------------------------------------------ transport

def _request(method: str, url: str, body: Optional[bytes] = None,
             content_type: str = "application/json",
             password: Optional[str] = None,
             user: Optional[str] = None) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", content_type)
    token = base64.b64encode(
        f"{user or ES_USER}:{password if password is not None else ES_PASSWORD}".encode()
    ).decode()
    request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT,
                                    context=ssl.create_default_context()) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, OSError, ssl.SSLError) as error:
        return 0, str(error).encode()


def es(method: str, path: str, payload: Any = None) -> Tuple[int, Any]:
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
    status, raw = _request(method, f"{ES_URL}{path}", body)
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw.decode("utf-8", "replace")


# ------------------------------------------------------------------ provisioning

def wait_for_elastic(attempts: int = 120) -> bool:
    for attempt in range(attempts):
        status, body = es("GET", "/_cluster/health?wait_for_status=yellow&timeout=5s")
        if status == 200:
            log(f"elasticsearch ready ({(body or {}).get('status', '?')})")
            return True
        if attempt % 10 == 0:
            log(f"waiting for elasticsearch... ({status})")
        time.sleep(5)
    log("elasticsearch never became ready")
    return False


def set_kibana_password() -> None:
    """Kibana authenticates as kibana_system, whose password ES does not preset.

    Doing it here rather than in a separate init container keeps the moving
    parts down: we already hold the elastic superuser credential. Kibana retries
    its own connection, so it recovers on its own once this lands.
    """
    if not KIBANA_PASSWORD:
        return
    status, body = es("POST", "/_security/user/kibana_system/_password",
                      {"password": KIBANA_PASSWORD})
    if status == 200:
        log("kibana_system password set")
    else:
        log(f"could not set kibana_system password: {status} {body}")


def ensure_ilm() -> None:
    """Age-based deletion only.

    Deliberately no rollover action: rollover requires the index to be the write
    target of an alias or data stream, and these are date-named indices written
    to directly, so ILM would drop every one of them into an ERROR step. Indices
    are already daily, which is what rollover would have been buying us.
    """
    policy = {
        "policy": {
            "phases": {
                # Captured attacker data is evidence; deletion is the operator's
                # retention decision, surfaced as ELASTIC_RETENTION_DAYS.
                "delete": {
                    "min_age": f"{RETENTION_DAYS}d",
                    "actions": {"delete": {}},
                },
            }
        }
    }
    status, body = es("PUT", f"/_ilm/policy/{ILM_POLICY}", policy)
    if status not in (200, 201):
        log(f"ilm policy failed: {status} {body}")


def ensure_pipeline() -> None:
    """Normalise timestamps and derive ECS-ish fields the Kibana maps expect."""
    pipeline = {
        "description": "Drosera honeypot events",
        "processors": [
            {"date": {
                "field": "timestamp",
                "target_field": "@timestamp",
                "formats": ["ISO8601"],
                "ignore_failure": True,
            }},
            {"set": {
                "field": "source.ip",
                "copy_from": "real_ip",
                "ignore_empty_value": True,
                "ignore_failure": True,
            }},
            {"set": {
                "field": "event.kind",
                "value": "alert",
                "ignore_failure": True,
            }},
        ],
    }
    status, body = es("PUT", f"/_ingest/pipeline/{PIPELINE}", pipeline)
    if status not in (200, 201):
        log(f"pipeline failed: {status} {body}")


def ensure_template() -> None:
    template = {
        "index_patterns": [f"{INDEX_PREFIX}-*"],
        "priority": 200,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,      # single node: a replica never allocates
                "index.default_pipeline": PIPELINE,
                "index.lifecycle.name": ILM_POLICY,
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "timestamp": {"type": "date"},
                    "real_ip": {"type": "ip"},
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "geo": {
                                "properties": {
                                    "location": {"type": "geo_point"},
                                    "country_iso_code": {"type": "keyword"},
                                    "country_name": {"type": "keyword"},
                                    "city_name": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "service": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    # text for searching, keyword for counting. Without the
                    # sub-field these can be matched but never aggregated, so
                    # "the twenty passwords most often tried" -- which is the
                    # obvious question to ask of this data -- is unanswerable
                    # in Kibana even though every attempt is stored.
                    #
                    # ignore_above is 512 rather than the usual 256 because
                    # alerting caps payload_excerpt at 500 characters, and a
                    # lower limit would silently drop the longest commands out
                    # of the aggregatable copy while leaving them searchable.
                    "reason": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword",
                                               "ignore_above": 512}},
                    },
                    "payload_excerpt": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword",
                                               "ignore_above": 512}},
                    },
                    "score_delta": {"type": "float"},
                    "cumulative_score": {"type": "float"},
                    "tool_detected": {"type": "keyword"},
                    "tarpit_active": {"type": "boolean"},
                    "banned": {"type": "boolean"},
                    "services_touched": {"type": "keyword"},
                    "fake_hostname": {"type": "keyword"},
                    "held_seconds": {"type": "float"},
                    "duration": {"type": "float"},
                }
            },
        },
    }
    status, body = es("PUT", f"/_index_template/{INDEX_PREFIX}", template)
    if status not in (200, 201):
        log(f"index template failed: {status} {body}")


def _kibana_post(path: str, payload: Dict[str, Any]) -> Tuple[int, bytes]:
    """Kibana rejects any state-changing request without the kbn-xsrf header."""
    request = urllib.request.Request(
        f"{KIBANA_URL}{path}", data=json.dumps(payload).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("kbn-xsrf", "true")
    token = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, OSError) as error:
        return 0, str(error).encode()


def ensure_kibana_data_view() -> bool:
    """Best-effort. Returns True once it exists, so the caller stops retrying.

    Kibana takes appreciably longer to come up than Elasticsearch, so this is
    attempted on each cycle rather than once at startup.
    """
    status, raw = _kibana_post("/api/data_views/data_view", {
        "data_view": {
            "title": f"{INDEX_PREFIX}-*",
            "name": "Drosera events",
            "timeFieldName": "@timestamp",
        }
    })
    if status in (200, 201):
        log("kibana data view created")
        return True

    # Kibana answers a duplicate with 400 and a message, not the 409 the shape
    # of the operation suggests. Treating that as failure meant the one status
    # it actually returns for "already done" was the one that kept it retrying
    # -- forever, once per cycle, for a view that existed the whole time.
    #
    # Matched on the message rather than the bare status: 400 is also what a
    # genuinely malformed request gets, and swallowing that would hide a real
    # error behind an assumption.
    detail = (raw or b"").decode("utf-8", "replace")
    if status == 400 and "duplicate" in detail.lower():
        log("kibana data view already present")
        return True
    if status == 409:
        return True

    log(f"kibana data view pending ({status}); will retry: {detail[:200]}")
    return False


# --------------------------------------------------------------- enrichment

def _geoip():
    global _geoip_reader
    if _geoip_reader is not None:
        return _geoip_reader
    if not GEOIP_DB.is_file():
        return None
    try:
        import maxminddb
        _geoip_reader = maxminddb.open_database(str(GEOIP_DB))
        log(f"geoip enabled from {GEOIP_DB}")
    except Exception as error:                          # noqa: BLE001
        log(f"geoip unavailable: {error}")
        _geoip_reader = None
    return _geoip_reader


def enrich(event: Dict[str, Any]) -> Dict[str, Any]:
    """Attach source.geo so Kibana's map visualisations have something to plot."""
    ip = event.get("real_ip")
    if not ip:
        return event

    geo: Dict[str, Any] = {}
    reader = _geoip()
    if reader is not None:
        try:
            record = reader.get(ip) or {}
            location = record.get("location") or {}
            country = record.get("country") or {}
            city = record.get("city") or {}
            if location.get("latitude") is not None:
                geo["location"] = {
                    "lat": location["latitude"],
                    "lon": location["longitude"],
                }
            if country.get("iso_code"):
                geo["country_iso_code"] = country["iso_code"]
            names = country.get("names") or {}
            if names.get("en"):
                geo["country_name"] = names["en"]
            city_names = city.get("names") or {}
            if city_names.get("en"):
                geo["city_name"] = city_names["en"]
        except Exception:                               # noqa: BLE001
            pass

    # Cloudflare already resolved the country for anything that came through the
    # proxy, so we get country-level geo on web traffic even with no MaxMind DB.
    if not geo.get("country_iso_code"):
        country_code = (event.get("headers") or {}).get("cf_ipcountry")
        if country_code and country_code != "XX":
            geo["country_iso_code"] = country_code

    if geo:
        event.setdefault("source", {})
        if isinstance(event["source"], dict):
            event["source"]["ip"] = ip
            event["source"]["geo"] = geo

    # Which deployment this came from. Only meaningful when several instances
    # ship to one Elasticsearch -- without it their events merge into an
    # undifferentiated pile and "which of my honeypots saw this" stops being
    # answerable. Absent by default, so a single-instance index is unchanged.
    if INSTANCE:
        event["instance"] = INSTANCE
    return event


# ------------------------------------------------------------------- shipping

def load_state() -> Dict[str, int]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def indexed_count() -> Optional[int]:
    """How many documents Elasticsearch is actually holding for us."""
    status, body = es("GET", f"/{INDEX_PREFIX}-*/_count")
    if status != 200 or not isinstance(body, dict):
        return None
    count = body.get("count")
    return count if isinstance(count, int) else None


def reconcile_state() -> None:
    """Drop the checkpoint if Elasticsearch has clearly lost what it describes.

    The checkpoint records how far into each log file we have read, and it lives
    on the storage volume -- not in Elasticsearch. Delete the search index and
    the two disagree silently: the shipper believes it already sent six days of
    events, the cluster holds none of them, and nothing reports an error. The
    only symptom is a dashboard whose numbers are an order of magnitude below
    the honeypot's own, which is a slow thing to notice and a confusing thing to
    diagnose.

    Re-shipping is safe rather than merely tolerable: document ids are
    sha1(file:offset), so a resend overwrites the same document. The cost of
    being wrong here is one redundant pass over the logs; the cost of not
    checking is data that never arrives.

    Deliberately a floor, not an equality check. Documents legitimately expire
    under ILM while the checkpoint keeps its offsets, so "fewer than we sent"
    is normal for an old deployment. Only an index that is empty, or nearly so,
    against a checkpoint claiming substantial progress means the index was
    reset underneath us.
    """
    state = load_state()
    if not state:
        return

    claimed = sum(v for v in state.values() if isinstance(v, int))
    if claimed < RESET_MIN_BYTES:
        return

    count = indexed_count()
    if count is None:                       # cluster unreachable; leave it be
        return
    if count > RESET_MAX_DOCS:
        return

    log(f"checkpoint claims {claimed} bytes shipped but the index holds "
        f"{count} documents -- reshipping from the start")
    try:
        STATE_FILE.unlink()
    except OSError as error:
        log(f"could not clear the checkpoint: {error}")


def save_state(state: Dict[str, int]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError as error:
        log(f"could not checkpoint offsets: {error}")


def index_for(event: Dict[str, Any], fallback: str) -> str:
    stamp = str(event.get("timestamp") or "")[:10]
    if len(stamp) == 10 and stamp[4] == "-":
        return f"{INDEX_PREFIX}-{stamp.replace('-', '.')}"
    return fallback


def bulk(actions: List[str]) -> bool:
    if not actions:
        return True
    body = ("\n".join(actions) + "\n").encode()
    request = urllib.request.Request(f"{ES_URL}/_bulk", data=body, method="POST")
    request.add_header("Content-Type", "application/x-ndjson")
    token = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            parsed = json.loads(response.read())
    except (urllib.error.HTTPError, urllib.error.URLError, OSError,
            json.JSONDecodeError) as error:
        log(f"bulk failed: {error}")
        return False

    if parsed.get("errors"):
        for item in parsed.get("items", []):
            result = item.get("index") or item.get("create") or {}
            if result.get("error"):
                log(f"bulk item rejected: {result['error'].get('reason')}")
                break
    return True


def ship_file(path: Path, state: Dict[str, int]) -> int:
    key = path.name
    offset = state.get(key, 0)
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    if size < offset:
        # logrotate uses copytruncate on this tree, which empties the file in
        # place. Anything written between our last read and the truncate went to
        # the rotated sibling, which we do not glob -- so a rotation can leave a
        # small gap in the index. The JSONL on disk stays the complete record.
        log(f"{key} was truncated (rotation); resuming from 0, "
            f"events between offset {offset} and the rotation are only on disk")
        offset = 0
    if size == offset:
        return 0

    fallback = f"{INDEX_PREFIX}-{path.stem.replace('-', '.')}"
    sent = 0
    actions: List[str] = []
    batch_start = offset

    try:
        # Binary mode deliberately: in text mode tell() returns an opaque cookie
        # that cannot be compared against st_size or reused as a stable ID.
        with open(path, "rb") as handle:
            handle.seek(offset)
            while True:
                line_start = handle.tell()
                raw = handle.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    # Partial final line: a writer is mid-append. Leave the
                    # offset before it so the whole line ships next cycle.
                    break
                offset = handle.tell()
                if len(raw) > MAX_LINE_BYTES:
                    continue
                stripped = raw.decode("utf-8", "replace").strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue

                doc_id = hashlib.sha1(f"{key}:{line_start}".encode()).hexdigest()
                actions.append(json.dumps({
                    "index": {"_index": index_for(event, fallback), "_id": doc_id}
                }))
                actions.append(json.dumps(enrich(event), default=str))
                sent += 1

                if len(actions) >= BATCH_LINES * 2:
                    if not bulk(actions):
                        # Roll back to the last acknowledged point.
                        state[key] = batch_start
                        save_state(state)
                        return 0
                    actions = []
                    batch_start = offset
                    state[key] = offset
                    save_state(state)
    except OSError as error:
        log(f"read failed on {key}: {error}")
        return 0

    if actions and not bulk(actions):
        state[key] = batch_start
        save_state(state)
        return 0

    state[key] = offset
    save_state(state)
    return sent


def log_files() -> List[Path]:
    """Every event log, including the rotated siblings.

    `*.jsonl` alone misses them, and missing them is silent: logrotate's
    copytruncate leaves `2026-07-28.jsonl` at zero bytes with the day's events
    in `2026-07-28.jsonl.1`, so the glob still matches a file and still reads it
    to the end. Fourteen megabytes of events were absent from the search index
    with nothing anywhere reporting a gap -- the shipper had genuinely read
    every byte it could see.

    The admin dashboard's read_day() already merges these; this is the same
    correction on the other reader. The stanza that created them is gone, so
    this is mostly about the files it left behind -- but a deployment that
    rotates these logs by some other means should not quietly lose them either.
    """
    if not LOG_DIR.is_dir():
        return []
    files = []
    for path in sorted(LOG_DIR.glob("*.jsonl*")):
        if path.suffix in (".gz", ".bz2", ".xz", ".zst"):
            # Offsets into a compressed stream are not byte offsets into the
            # events, so the checkpoint would be meaningless. Named rather than
            # skipped in silence, which is the failure this whole function is
            # correcting.
            log(f"skipping compressed log {path.name}; decompress it to ship it")
            continue
        if path.is_file():
            files.append(path)
    return files


def cycle() -> int:
    state = load_state()
    total = 0
    for path in log_files():
        total += ship_file(path, state)
    return total


def provision() -> None:
    set_kibana_password()
    ensure_ilm()
    ensure_pipeline()
    ensure_template()


def main() -> int:
    if not ES_PASSWORD:
        log("ELASTIC_PASSWORD is empty; refusing to start")
        return 1

    if not wait_for_elastic():
        return 1
    provision()
    # After provision(), so the template and pipeline exist before anything is
    # re-sent, and before the first cycle reads the checkpoint.
    reconcile_state()

    if "--once" in sys.argv:
        log(f"shipped {cycle()} events")
        return 0

    kibana_ready = False
    last_report = 0.0
    shipped = 0

    while True:
        try:
            shipped += cycle()
            if not kibana_ready:
                kibana_ready = ensure_kibana_data_view()
            if time.time() - last_report > 300:
                log(f"{shipped} events shipped since start")
                last_report = time.time()
        except Exception as error:                      # noqa: BLE001
            log(f"cycle failed: {type(error).__name__}: {error}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
