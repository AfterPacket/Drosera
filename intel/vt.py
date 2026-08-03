"""VirusTotal enrichment for quarantined payloads.

Runs in its own container on cam-egress -- the only network permitted outbound
-- and has no listening ports. The honeypots that captured the sample cannot
reach the internet, and this cannot be reached from the internet, so a
compromise of either does not become a compromise of both.

WHAT THIS SENDS, AND WHY IT MATTERS
-----------------------------------
By default it sends a SHA-256 and nothing else. That is a lookup: "has anyone
seen this?" It does not disclose the file.

Uploading the *sample* is a different act with consequences that are easy to
miss. VirusTotal distributes submitted files to its paying customers, and the
threat-intelligence market includes the people who wrote the malware. Groups
routinely monitor VT for their own samples. Upload a targeted payload and you
may:

  * tell the operator their implant was caught, roughly when, and -- via first
    submission metadata and timing -- roughly where;
  * publish whatever the sample embeds, which for a targeted dropper can
    include a hardcoded C2, a victim identifier, or credentials that are not
    yours to disclose;
  * burn the visibility you were collecting.

For commodity botnet junk none of that matters and the hash will already be
known. For anything interesting it matters a great deal. So uploads are opt-in
per run (VT_UPLOAD_SAMPLES=1) rather than the default, and the log says plainly
what was sent.

Nothing here opens, parses or executes a sample. It reads bytes, hashes them,
and talks to an HTTPS API. Detonation belongs on a machine you are willing to
lose, not on the box taking the attacks.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, "/app")

from shared import alerting, loot  # noqa: E402

# Where the dashboard leaves rescan markers. It mounts storage/ read-only and
# shares no network with this container, so a file on the volume is the whole
# channel -- the same shape as llm-broker's request directory, and for the same
# reason: the component that can reach the internet must not be reachable from
# the one an operator points a browser at.
REQUEST_DIR = Path(os.getenv("REQUEST_DIR", "/var/honeypot/storage/requests"))

API_KEY = os.getenv("VT_API_KEY", "").strip()
UPLOAD_SAMPLES = os.getenv("VT_UPLOAD_SAMPLES", "0") == "1"
POLL_SECONDS = int(os.getenv("VT_POLL_SECONDS", "300"))

# The free tier is 4 requests/minute and 500/day. Going over gets the key
# throttled, so pace well inside it rather than discovering the limit live.
REQUEST_INTERVAL = float(os.getenv("VT_REQUEST_INTERVAL", "20"))
MAX_PER_RUN = int(os.getenv("VT_MAX_PER_RUN", "20"))

API = "https://www.virustotal.com/api/v3/files/"

# Distinct from None. None means "this one failed, try the next"; this means
# "stop asking" -- and conflating them is how one exhausted quota turned into
# twenty more requests against it, every five minutes, for the rest of the day.
RATE_LIMITED = object()


def log(message: str) -> None:
    print(f"[vt] {message}", flush=True)


STATUS_PATH = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage")) / "intel" / "status.json"


def publish_status(**extra) -> None:
    """Say on the volume whether scanning is configured and running.

    The dashboard needs to tell "pending" from "nothing is scanning at all",
    and the difference is invisible in the loot sidecars -- both look like an
    absent verdict. It is answered here rather than by handing the dashboard
    VT_API_KEY, which it has no egress to use and no business holding, the same
    position docker-compose.yml takes on the SMTP credentials. llm-broker
    publishes its own status the same way.

    Never fatal: a status file that cannot be written is a cosmetic loss, and
    this runs inside the loop that does the actual work.
    """
    try:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "vt_configured": bool(API_KEY),
            "poll_seconds": POLL_SECONDS,
            "updated": time.time(),
        }
        payload.update(extra)
        STATUS_PATH.write_text(json.dumps(payload), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        pass


def lookup(digest: str):
    """Ask VirusTotal about a hash.

    Returns the verdict dict, None for a retryable failure, or RATE_LIMITED --
    which the caller must treat as "stop", not as "try the next one".
    """
    request = urllib.request.Request(
        API + urllib.parse.quote(digest, safe=""),
        headers={"x-apikey": API_KEY, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"known": False, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                time.gmtime())}
        if error.code == 429:
            # The body is the only thing that distinguishes the per-minute rate
            # from the daily 500 and the monthly cap, and those want completely
            # different responses -- wait a minute, wait for midnight UTC, or
            # wait for next month. Logging the code alone left an operator
            # unable to tell which, staring at twenty identical lines.
            detail = ""
            try:
                detail = json.loads(error.read().decode("utf-8", "replace")) \
                    .get("error", {}).get("message", "")
            except Exception:                                   # noqa: BLE001
                pass
            log(f"VirusTotal refused: HTTP 429 {detail or '(no detail given)'}")
            return RATE_LIMITED
        log(f"lookup {digest[:16]} failed: HTTP {error.code}")
        return None
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as error:
        log(f"lookup {digest[:16]} failed: {error}")
        return None

    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    names = attributes.get("names") or []

    return {
        "known": True,
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "label": (attributes.get("popular_threat_classification") or {})
                 .get("suggested_threat_label", ""),
        "type": attributes.get("type_description", ""),
        "first_submitted": attributes.get("first_submission_date"),
        "names": names[:5],
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uploaded_by_us": False,
    }


def take_rescan_requests() -> int:
    """Honour any rescan markers the dashboard has left, then delete them.

    A marker is a file named <sha256>.rescan. The name carries the whole
    request, so nothing here parses attacker-influenced content -- and the
    digest is validated by loot.clear_scan() before it is used, which is the
    only reason a filename from another container is safe to act on.

    Clearing the verdict is all this does. The sample then reappears in
    pending_scan() and takes its turn in the ordinary rate-limited loop below,
    so a fistful of rescan clicks cannot burst past the VT quota.
    """
    if not REQUEST_DIR.is_dir():
        return 0

    taken = 0
    try:
        markers = sorted(REQUEST_DIR.glob("*.rescan"))
    except OSError:
        return 0

    for marker in markers:
        digest = marker.stem
        if loot.clear_scan(digest):
            taken += 1
            log(f"{digest[:16]} queued for rescan by operator")
        else:
            log(f"ignoring rescan marker {marker.name!r}: unknown or bad digest")
        # Removed either way. A marker naming a sample that is gone would
        # otherwise be retried every poll for as long as the volume lives.
        try:
            marker.unlink()
        except OSError:
            pass
    return taken


def run_once() -> None:
    take_rescan_requests()

    pending = loot.pending_scan()
    if not pending:
        return

    log(f"{len(pending)} sample(s) awaiting a verdict")

    for digest in pending[:MAX_PER_RUN]:
        verdict = lookup(digest)
        if verdict is RATE_LIMITED:
            # Abandon the whole run, not just this sample. Everything stays
            # pending and the next poll retries -- costing one request to find
            # out we are still blocked, rather than the twenty it used to spend
            # discovering the same thing nineteen more times.
            log(f"{len(pending)} sample(s) still pending; retrying next poll")
            return
        if verdict is None:
            # Leave it pending; a transient API failure should be retried, not
            # recorded as "clean".
            time.sleep(REQUEST_INTERVAL)
            continue

        loot.record_scan(digest, verdict)

        if verdict.get("known") and verdict.get("malicious", 0) > 0:
            meta = loot.read_meta(digest) or {}
            sightings = meta.get("sightings") or []
            source = sightings[-1].get("ip", "") if sightings else ""
            # "unlabelled", not "unknown". VirusTotal populates
            # suggested_threat_label only when a popular classification exists,
            # and type_description can be empty too -- so a flagged sample can
            # arrive with no name at all. Calling that "unknown" collided with
            # the LOOT_UNKNOWN path below, where the word means the opposite
            # thing: nobody has ever seen it. Same string, two meanings, one
            # bucket in every aggregation.
            label = verdict.get("label") or verdict.get("type") or "unlabelled"
            log(f"{digest[:16]} MALICIOUS {verdict['malicious']} engines: {label}")
            alerting.alert_event(
                source or "0.0.0.0", "LOOT_MALICIOUS", service="intel",
                payload=(f"{digest} flagged by {verdict['malicious']} engines "
                         f"({label})")[:200],
                # Structured as well as narrated. The sentence above is what an
                # operator reads in an alert; these are what Kibana can group
                # by, and without them "which sample keeps coming back" and
                # "which family dominates" are unanswerable -- the digest was
                # only ever inside a phrase.
                loot_sha256=digest,
                loot_size=int(meta.get("size") or 0),
                vt_malicious=int(verdict.get("malicious") or 0),
                vt_label=label,
            )
        elif verdict.get("known"):
            log(f"{digest[:16]} known, 0 detections")
            # Recorded but not alerted. This is the boring outcome and stays
            # out of the notable set, but a verdict breakdown that omits it is
            # not a breakdown -- it would show malicious against unknown and
            # silently drop every sample that came back clean, making the
            # quarantine look far worse than it is.
            meta = loot.read_meta(digest) or {}
            sightings = meta.get("sightings") or []
            alerting.alert_event(
                (sightings[-1].get("ip", "") if sightings else "") or "0.0.0.0",
                "LOOT_CLEAN", service="intel",
                payload=f"{digest} known to VirusTotal, 0 detections"[:200],
                loot_sha256=digest,
                loot_size=int(meta.get("size") or 0),
                vt_malicious=0,
                vt_label="clean",
            )
        else:
            # Unknown to VT is the interesting case, not the boring one: it
            # means nobody has submitted it, which for a live drop suggests
            # something new or something targeted.
            log(f"{digest[:16]} UNKNOWN to VirusTotal -- new or targeted")
            meta = loot.read_meta(digest) or {}
            sightings = meta.get("sightings") or []
            source = sightings[-1].get("ip", "") if sightings else ""
            alerting.alert_event(
                source or "0.0.0.0", "LOOT_UNKNOWN", service="intel",
                payload=f"{digest} unknown to VirusTotal ({meta.get('size', 0)}B)"[:200],
                loot_sha256=digest,
                loot_size=int(meta.get("size") or 0),
                vt_malicious=0,
                # Distinct from "unlabelled" above, which is a flagged sample
                # nobody named. This one is a sample nobody has submitted --
                # for a live drop, the more interesting of the two.
                vt_label="not-in-vt",
            )

        time.sleep(REQUEST_INTERVAL)


def main() -> None:
    if not API_KEY:
        log("VT_API_KEY not set; samples will be quarantined but not scanned.")
        log("Quarantine still works: storage/loot/ holds the payloads and hashes.")
        # Still drained, on the ordinary poll rather than hourly. Nothing can be
        # scanned without a key, but the dashboard's rescan button writes a
        # marker regardless, and markers nobody collects accumulate on the
        # volume forever -- a slow leak in the one directory the operator UI can
        # write to. Clearing the verdict is also still the right thing to do:
        # the sample goes back to pending, so it is picked up the moment a key
        # is added rather than staying stuck on a stale answer.
        while True:
            publish_status()
            try:
                if take_rescan_requests():
                    log("rescans queued, but VT_API_KEY is unset -- "
                        "they stay pending until one is configured")
            except Exception as error:
                log(f"rescan sweep failed: {error}")
            time.sleep(POLL_SECONDS)

    if UPLOAD_SAMPLES:
        log("VT_UPLOAD_SAMPLES=1 is set but uploading is not implemented here.")
        log("Hash lookups only. Submit by hand if you have decided it is safe;")
        log("see the module docstring for why that decision deserves thought.")

    log(f"watching {loot.LOOT_DIR} every {POLL_SECONDS}s (hash lookups only)")
    while True:
        publish_status(pending=len(loot.pending_scan()))
        try:
            run_once()
        except Exception as error:          # never let the loop die
            log(f"cycle failed: {error}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
