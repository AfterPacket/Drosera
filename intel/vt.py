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

sys.path.insert(0, "/app")

from shared import alerting, loot  # noqa: E402

API_KEY = os.getenv("VT_API_KEY", "").strip()
UPLOAD_SAMPLES = os.getenv("VT_UPLOAD_SAMPLES", "0") == "1"
POLL_SECONDS = int(os.getenv("VT_POLL_SECONDS", "300"))

# The free tier is 4 requests/minute and 500/day. Going over gets the key
# throttled, so pace well inside it rather than discovering the limit live.
REQUEST_INTERVAL = float(os.getenv("VT_REQUEST_INTERVAL", "20"))
MAX_PER_RUN = int(os.getenv("VT_MAX_PER_RUN", "20"))

API = "https://www.virustotal.com/api/v3/files/"


def log(message: str) -> None:
    print(f"[vt] {message}", flush=True)


def lookup(digest: str):
    """Ask VirusTotal about a hash. Returns the verdict dict, or None."""
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


def run_once() -> None:
    pending = loot.pending_scan()
    if not pending:
        return

    log(f"{len(pending)} sample(s) awaiting a verdict")

    for digest in pending[:MAX_PER_RUN]:
        verdict = lookup(digest)
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
            label = verdict.get("label") or verdict.get("type") or "unknown"
            log(f"{digest[:16]} MALICIOUS {verdict['malicious']} engines: {label}")
            alerting.alert_event(
                source or "0.0.0.0", "LOOT_MALICIOUS", service="intel",
                payload=(f"{digest} flagged by {verdict['malicious']} engines "
                         f"({label})")[:200],
            )
        elif verdict.get("known"):
            log(f"{digest[:16]} known, 0 detections")
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
            )

        time.sleep(REQUEST_INTERVAL)


def main() -> None:
    if not API_KEY:
        log("VT_API_KEY not set; samples will be quarantined but not scanned.")
        log("Quarantine still works: storage/loot/ holds the payloads and hashes.")
        while True:
            time.sleep(3600)

    if UPLOAD_SAMPLES:
        log("VT_UPLOAD_SAMPLES=1 is set but uploading is not implemented here.")
        log("Hash lookups only. Submit by hand if you have decided it is safe;")
        log("see the module docstring for why that decision deserves thought.")

    log(f"watching {loot.LOOT_DIR} every {POLL_SECONDS}s (hash lookups only)")
    while True:
        try:
            run_once()
        except Exception as error:          # never let the loop die
            log(f"cycle failed: {error}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
