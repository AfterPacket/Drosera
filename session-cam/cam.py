#!/usr/bin/env python3
"""Drosera session camera: render finished attacker sessions and deliver them.

Watches storage/sessions for the .meta.json sidecars the recorders drop when a
session closes, renders the matching .cast to a clip, and pushes it out over
Telegram and/or email. The dashboard serves the same clips without needing any
of this.

CONTAINMENT
    This is the only container in the appliance with internet access, so it is
    deliberately kept off honeypot-internal. It receives recordings through the
    shared storage volume -- a filesystem handoff, not a network one -- which
    means compromising it yields no route back into the honeypot network, and
    compromising a honeypot yields no route out through it.

Every recording it parses is attacker-controlled input, so a failure on one
session is logged and skipped; it must never take the watcher down.
"""

import json
import os
import secrets
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from render import CastError, render_gif, render_mp4

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
SESSION_DIR = STORAGE_DIR / "sessions"
CLIP_DIR = STORAGE_DIR / "clips"

ENABLED = os.getenv("CAM_ENABLED", "true").lower() not in ("0", "false", "no")
POLL_SECONDS = int(os.getenv("CAM_POLL_SECONDS", "15"))
MAX_PER_CYCLE = int(os.getenv("CAM_MAX_PER_CYCLE", "20"))

# Gating. Most recordings are a scanner connecting and leaving; without a floor
# the useful clips drown in noise.
MIN_SCORE = float(os.getenv("CAM_MIN_SCORE", "5"))
MIN_DURATION = float(os.getenv("CAM_MIN_DURATION", "2"))
# Content floor, checked alongside duration rather than instead of it. Duration
# measures how long the socket stayed open, which correlates poorly with whether
# anything happened: a bot that dumps 3 KB of probe output in half a second is
# worth far more than an idle connection held for ten seconds.
MIN_BYTES = int(os.getenv("CAM_MIN_BYTES", "700"))
# Two frames is one real exchange -- a webshell command and its output, or a
# banner and a prompt. Below that there is nothing to watch.
MIN_FRAMES = int(os.getenv("CAM_MIN_FRAMES", "2"))

CLIP_FORMAT = os.getenv("CAM_FORMAT", "gif").lower().strip()
if CLIP_FORMAT not in ("gif", "mp4", "both"):
    # A typo here would otherwise mean rendering everything and delivering none.
    CLIP_FORMAT = "gif"
RETENTION_DAYS = int(os.getenv("CAM_RETENTION_DAYS", "14"))
MAX_CLIP_MB = float(os.getenv("CAM_MAX_CLIP_MB", "45"))   # Telegram caps at 50
MAX_CLIPS_MB = float(os.getenv("CAM_MAX_CLIPS_TOTAL_MB", "1024"))
TIMEOUT = float(os.getenv("ALERT_TIMEOUT_SECONDS", "20"))

TELEGRAM_TOKEN = os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("ALERT_TELEGRAM_CHAT_ID", "").strip()
WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()

SMTP_HOST = os.getenv("CAM_SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("CAM_SMTP_PORT", "587"))
SMTP_USER = os.getenv("CAM_SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("CAM_SMTP_PASSWORD", "")
SMTP_SECURITY = os.getenv("CAM_SMTP_SECURITY", "starttls").lower()  # starttls|ssl|none
MAIL_FROM = os.getenv("CAM_MAIL_FROM", "").strip()
MAIL_TO = [a.strip() for a in os.getenv("CAM_MAIL_TO", "").split(",") if a.strip()]


def log(message: str) -> None:
    print(f"[cam] {message}", flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------- descriptions

def caption(meta: Dict[str, Any]) -> str:
    credentials = meta.get("credentials") or []
    lines = [
        f"[drosera cam] {meta.get('service', '?')} session",
        f"IP: {meta.get('ip', 'unknown')}",
        f"When: {str(meta.get('started_at', ''))[:19].replace('T', ' ')}Z",
        f"Duration: {meta.get('duration', 0)}s",
        f"Score: {meta.get('score', '-')}",
        f"Tool: {meta.get('tool') or 'none'}",
        f"Services: {', '.join(meta.get('services_touched') or []) or 'n/a'}",
        f"Presented as: {meta.get('fake_hostname') or '-'}",
    ]
    if credentials:
        lines.append("Creds tried: " + ", ".join(credentials[:5]))
    if meta.get("banned"):
        lines.append("Status: BANNED")
    elif meta.get("tarpit_active"):
        lines.append("Status: TARPITTED")
    if meta.get("truncated"):
        lines.append("Note: recording hit the size cap and was truncated.")
    # Telegram rejects media captions over 1024 characters.
    return "\n".join(lines)[:1000]


# ----------------------------------------------------------------- delivery

def _multipart(fields: Dict[str, str], file_field: str, filename: str,
               content: bytes, content_type: str) -> Tuple[bytes, str]:
    boundary = "----droseracam" + secrets.token_hex(16)
    body = bytearray()
    for key, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
        body += str(value).encode("utf-8") + b"\r\n"
    body += f"--{boundary}\r\n".encode()
    body += (f'Content-Disposition: form-data; name="{file_field}"; '
             f'filename="{filename}"\r\n').encode()
    body += f"Content-Type: {content_type}\r\n\r\n".encode()
    body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def send_telegram(clip: Path, meta: Dict[str, Any]) -> Optional[str]:
    """Returns None on success, or an error string."""
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        return "not configured"

    is_mp4 = clip.suffix == ".mp4"
    method = "sendVideo" if is_mp4 else "sendAnimation"
    field = "video" if is_mp4 else "animation"
    mime = "video/mp4" if is_mp4 else "image/gif"

    try:
        content = clip.read_bytes()
    except OSError as error:
        return f"read failed: {error}"

    body, content_type = _multipart(
        {"chat_id": TELEGRAM_CHAT_ID, "caption": caption(meta)},
        field, clip.name, content, mime,
    )
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/{method}",
        data=body, headers={"Content-Type": content_type}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                return f"http {response.status}"
    except urllib.error.HTTPError as error:
        return f"http {error.code}: {error.read()[:200].decode('utf-8', 'replace')}"
    except (urllib.error.URLError, OSError) as error:
        return f"network: {error}"
    return None


def send_email(clip: Path, meta: Dict[str, Any]) -> Optional[str]:
    if not (SMTP_HOST and MAIL_FROM and MAIL_TO):
        return "not configured"

    message = EmailMessage()
    message["Subject"] = (f"[drosera] {meta.get('service', '?')} session from "
                          f"{meta.get('ip', 'unknown')}")
    message["From"] = MAIL_FROM
    message["To"] = ", ".join(MAIL_TO)
    message.set_content(caption(meta))

    try:
        content = clip.read_bytes()
    except OSError as error:
        return f"read failed: {error}"

    subtype = "mp4" if clip.suffix == ".mp4" else "gif"
    maintype = "video" if clip.suffix == ".mp4" else "image"
    message.add_attachment(content, maintype=maintype, subtype=subtype,
                           filename=clip.name)

    try:
        if SMTP_SECURITY == "ssl":
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT)
        with server:
            if SMTP_SECURITY == "starttls":
                server.starttls(context=ssl.create_default_context())
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as error:
        return f"smtp: {error}"
    return None


def send_webhook(clip: Path, meta: Dict[str, Any]) -> Optional[str]:
    """Metadata only -- the clip itself stays on the box and in the dashboard."""
    if not WEBHOOK_URL:
        return "not configured"
    payload = {
        "timestamp": _now(),
        "event_type": "SESSION_CLIP",
        "real_ip": meta.get("ip"),
        "service": meta.get("service"),
        "duration": meta.get("duration"),
        "cumulative_score": meta.get("score"),
        "tool_detected": meta.get("tool") or None,
        "clip": clip.name,
        "cast": meta.get("cast"),
        "summary": caption(meta),
    }
    request = urllib.request.Request(
        WEBHOOK_URL, data=json.dumps(payload, default=str).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "drosera-cam/1.0"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=TIMEOUT).close()
    except (urllib.error.URLError, OSError) as error:
        return f"network: {error}"
    return None


# ------------------------------------------------------------------ pipeline

def should_send(meta: Dict[str, Any]) -> Optional[str]:
    """Returns a skip reason, or None when the session is worth a clip."""
    if float(meta.get("score") or 0) < MIN_SCORE:
        return f"score {meta.get('score')} below {MIN_SCORE}"
    if int(meta.get("frames") or 0) < MIN_FRAMES:
        return f"only {meta.get('frames')} frames"
    # Either enough content or enough time. Requiring both discarded the most
    # interesting captures -- fast, dense probe output -- while keeping idle
    # sockets that recorded nothing but a banner.
    written = int(meta.get("bytes") or 0)
    elapsed = float(meta.get("duration") or 0)
    if written < MIN_BYTES and elapsed < MIN_DURATION:
        return f"{written}B in {elapsed}s: below both content and time floors"
    return None


def render_clips(cast: Path, stem: str, meta: Dict[str, Any]) -> List[Path]:
    clips: List[Path] = []
    gif = render_gif(cast, CLIP_DIR / f"{stem}.gif", meta)
    if CLIP_FORMAT in ("gif", "both"):
        clips.append(gif)
    if CLIP_FORMAT in ("mp4", "both"):
        mp4 = render_mp4(gif, CLIP_DIR / f"{stem}.mp4")
        if mp4 is not None:
            clips.append(mp4)
        elif not clips:
            # ffmpeg absent and mp4 was the only requested format.
            log("ffmpeg unavailable, falling back to gif")
            clips.append(gif)
        if CLIP_FORMAT == "mp4" and gif.is_file() and gif not in clips:
            gif.unlink(missing_ok=True)
    return clips


def deliver(clips: List[Path], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Send the best available clip on each configured channel."""
    # Prefer mp4 where we have both: smaller, and it plays inline everywhere.
    ordered = sorted(clips, key=lambda p: 0 if p.suffix == ".mp4" else 1)
    sendable = [c for c in ordered
                if c.stat().st_size <= MAX_CLIP_MB * 1024 * 1024]

    results: Dict[str, Any] = {}
    if not sendable:
        size = max((c.stat().st_size for c in ordered), default=0)
        results["oversize"] = f"clip is {size / 1048576:.1f}MB, over {MAX_CLIP_MB}MB"
        # Still tell the operator it happened, even without the footage.
        if WEBHOOK_URL:
            results["webhook"] = send_webhook(ordered[0], meta) or "sent"
        return results

    clip = sendable[0]
    if TELEGRAM_TOKEN:
        results["telegram"] = send_telegram(clip, meta) or "sent"
    if SMTP_HOST:
        results["email"] = send_email(clip, meta) or "sent"
    if WEBHOOK_URL:
        results["webhook"] = send_webhook(clip, meta) or "sent"
    return results


def process(meta_path: Path) -> bool:
    """Render and deliver one session. False means 'not yet, try again later'."""
    stem = meta_path.name[: -len(".meta.json")]
    marker = SESSION_DIR / f"{stem}.cam.json"
    if marker.exists():
        return False

    record: Dict[str, Any] = {"processed_at": _now(), "session": stem}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        record["error"] = f"unreadable sidecar: {error}"
        _write_marker(marker, record)
        return True

    # The webshell is stateless HTTP and has no connection close to end a
    # recording, so its sidecar carries a deadline instead. Leave it alone until
    # the attacker has gone quiet, or we would ship a clip mid-session and never
    # revisit it.
    open_until = meta.get("open_until")
    if open_until:
        try:
            if time.time() < float(open_until):
                return False
        except (TypeError, ValueError):
            pass

    skip = should_send(meta)
    if skip:
        record["skipped"] = skip
        _write_marker(marker, record)
        return True

    cast = SESSION_DIR / str(meta.get("cast") or f"{stem}.cast")
    if not cast.is_file():
        record["error"] = "cast missing"
        _write_marker(marker, record)
        return True

    started = time.time()
    try:
        clips = render_clips(cast, stem, meta)
    except CastError as error:
        record["error"] = str(error)
        _write_marker(marker, record)
        return True
    except Exception as error:                          # noqa: BLE001
        record["error"] = f"render failed: {type(error).__name__}: {error}"
        log(record["error"])
        _write_marker(marker, record)
        return True

    record["render_seconds"] = round(time.time() - started, 1)
    record["clips"] = [{"name": c.name, "bytes": c.stat().st_size} for c in clips]
    record["delivery"] = deliver(clips, meta)
    _write_marker(marker, record)
    log(f"{stem}: {record['delivery']}")
    return True


def _write_marker(marker: Path, record: Dict[str, Any]) -> None:
    try:
        marker.write_text(json.dumps(record, default=str), encoding="utf-8")
    except OSError as error:
        log(f"could not write marker {marker.name}: {error}")


def prune() -> None:
    """Age out clips, and enforce a total size ceiling oldest-first.

    The recordings themselves are evidence and are left to logrotate; clips are
    a convenience and are cheap to re-render from the .cast if ever needed.
    """
    if not CLIP_DIR.is_dir():
        return
    cutoff = time.time() - RETENTION_DAYS * 86400
    clips = []
    for clip in CLIP_DIR.iterdir():
        if not clip.is_file():
            continue
        try:
            stat = clip.stat()
        except OSError:
            continue
        if stat.st_mtime < cutoff:
            clip.unlink(missing_ok=True)
            continue
        clips.append((stat.st_mtime, stat.st_size, clip))

    total = sum(size for _, size, _ in clips)
    ceiling = MAX_CLIPS_MB * 1024 * 1024
    for _, size, clip in sorted(clips):
        if total <= ceiling:
            break
        clip.unlink(missing_ok=True)
        total -= size


def cycle() -> int:
    if not SESSION_DIR.is_dir():
        return 0
    CLIP_DIR.mkdir(parents=True, exist_ok=True)
    done = 0
    # Oldest first, so a backlog drains in the order it happened.
    for meta_path in sorted(SESSION_DIR.glob("*.meta.json"), key=lambda p: p.name):
        if done >= MAX_PER_CYCLE:
            break
        try:
            # Only real work counts against the budget, so a batch of still-open
            # webshell sessions cannot starve recordings that are ready to ship.
            if process(meta_path):
                done += 1
        except Exception as error:                      # noqa: BLE001
            log(f"unhandled error on {meta_path.name}: {type(error).__name__}: {error}")
            done += 1
    return done


def describe_config() -> str:
    channels = []
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        channels.append("telegram")
    if SMTP_HOST and MAIL_FROM and MAIL_TO:
        channels.append("email")
    if WEBHOOK_URL:
        channels.append("webhook")
    return (f"format={CLIP_FORMAT} min_score={MIN_SCORE} "
            f"channels={','.join(channels) or 'none (dashboard playback only)'}")


def main() -> int:
    if "--render" in sys.argv:
        # Manual check: render one cast and exit without sending anything.
        index = sys.argv.index("--render")
        cast = Path(sys.argv[index + 1])
        meta_path = cast.with_suffix(".meta.json")
        meta = {}
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        out = render_gif(cast, CLIP_DIR / f"{cast.stem}.gif", meta)
        print(f"wrote {out} ({out.stat().st_size} bytes)")
        return 0

    if not ENABLED:
        log("disabled via CAM_ENABLED, idling")
        while True:
            time.sleep(3600)

    log(f"session camera up: {describe_config()}")
    if "--once" in sys.argv:
        cycle()
        prune()
        return 0

    last_prune = 0.0
    while True:
        try:
            cycle()
            if time.time() - last_prune > 3600:
                prune()
                last_prune = time.time()
        except Exception as error:                      # noqa: BLE001
            log(f"cycle failed: {type(error).__name__}: {error}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
