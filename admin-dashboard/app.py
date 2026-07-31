#!/usr/bin/env python3
"""Drosera operator dashboard.

Deliberately shares nothing with the honeypot: its own Redis instance, its own
auth, its own network. It opens redis-honeypot read-only, and the only writes it
ever makes there are explicit operator ban/unban actions.

Auth is two-stage and both stages are required. A session is only created after
TOTP succeeds -- there is no intermediate state that grants access.
"""

import csv
import fnmatch
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import pyotp
import redis

import geoip
from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, send_file, stream_with_context, url_for)

app = Flask(__name__)

CONFIG_FILE = Path(os.getenv("ADMIN_CONFIG", "/app/config/admin-config.json"))
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
CLIP_DIR = STORAGE_DIR / "clips"
AUDIT_LOG = Path(os.getenv("AUDIT_LOG", "/app/admin-logs/audit.jsonl"))

SESSION_COOKIE = "sb_session"
SESSION_TTL = int(os.getenv("ADMIN_SESSION_TTL", str(8 * 3600)))
LOGIN_WINDOW = int(os.getenv("ADMIN_LOGIN_WINDOW", "900"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("ADMIN_LOGIN_MAX_ATTEMPTS", "5"))
PENDING_TTL = 300
STATS_CACHE_TTL = 30

BAN_TTL = int(os.getenv("HONEYPOT_BAN_TTL", str(7 * 24 * 3600)))

# Kibana is reached by the operator's own browser over their SSH tunnel, not by
# this container -- which is on neither elastic-internal nor any egress network.
# So this is a link target, never something the dashboard connects to.
KIBANA_URL = os.getenv("KIBANA_PUBLIC_URL", "").strip()

# Event types whose payload is something the attacker ran or wrote, rather than
# a status change. These are what "Commands issued" should show.
COMMAND_EVENTS = {
    "WEBSHELL_CMD",
    "DROPPED_BINARY_EXEC",
    "PERSISTENCE_ATTEMPT",
    "REVERSE_SHELL",
    "FILE_UPLOAD",
    "PHP_EVAL_ATTEMPT",
    "LOOT_CAPTURED",
}


@app.context_processor
def inject_nav():
    return {"kibana_url": KIBANA_URL}


def _redis_admin() -> redis.Redis:
    if "redis_admin" not in g:
        g.redis_admin = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis-admin"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            decode_responses=True, socket_connect_timeout=3, socket_timeout=3,
        )
    return g.redis_admin


def _redis_honeypot() -> redis.Redis:
    if "redis_honeypot" not in g:
        g.redis_honeypot = redis.Redis(
            host=os.getenv("REDIS_HONEYPOT_HOST", "redis-honeypot"),
            port=int(os.getenv("REDIS_HONEYPOT_PORT", "6379")),
            decode_responses=True, socket_connect_timeout=3, socket_timeout=3,
        )
    return g.redis_honeypot


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def audit(event: str, **details) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "remote_addr": request.remote_addr if request else None,
        "user": getattr(g, "admin_user", None),
        **details,
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass


# ------------------------------------------------------------------ security

@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        # No third-party origins: the player is served from static/ now, so the
        # dashboard loads nothing it does not host itself.
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def client_ip() -> str:
    """Trust only the immediate peer. This app is never behind a proxy we control."""
    return request.remote_addr or "0.0.0.0"


def ip_allowed(config: dict) -> bool:
    patterns = config.get("allowed_ips") or ["127.0.0.1"]
    peer = client_ip()
    return any(fnmatch.fnmatch(peer, pattern) for pattern in patterns)


def login_attempts_exceeded() -> bool:
    key = f"admin:login_attempts:{hashlib.sha256(client_ip().encode()).hexdigest()}"
    try:
        count = _redis_admin().get(key)
        return int(count or 0) >= LOGIN_MAX_ATTEMPTS
    except (redis.RedisError, ValueError):
        return False


def record_login_failure() -> None:
    key = f"admin:login_attempts:{hashlib.sha256(client_ip().encode()).hexdigest()}"
    try:
        pipe = _redis_admin().pipeline()
        pipe.incr(key)
        pipe.expire(key, LOGIN_WINDOW)
        pipe.execute()
    except redis.RedisError:
        pass


def clear_login_failures() -> None:
    key = f"admin:login_attempts:{hashlib.sha256(client_ip().encode()).hexdigest()}"
    try:
        _redis_admin().delete(key)
    except redis.RedisError:
        pass


def create_session(username: str) -> str:
    token = secrets.token_hex(32)
    payload = {
        "user": username,
        "ip": client_ip(),
        "csrf": secrets.token_hex(32),
        "created": time.time(),
    }
    _redis_admin().setex(f"admin:session:{token}", SESSION_TTL, json.dumps(payload))
    return token


def load_session():
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None, None
    try:
        raw = _redis_admin().get(f"admin:session:{token}")
    except redis.RedisError:
        return None, None
    if not raw:
        return None, None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None, None
    # Bind the session to the address that created it.
    if payload.get("ip") != client_ip():
        return None, None
    return token, payload


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token, payload = load_session()
        if payload is None:
            response = redirect(url_for("login"))
            response.delete_cookie(SESSION_COOKIE)
            return response
        g.admin_user = payload["user"]
        g.csrf_token = payload["csrf"]
        g.session_token = token
        try:
            _redis_admin().expire(f"admin:session:{token}", SESSION_TTL)
        except redis.RedisError:
            pass
        return view(*args, **kwargs)
    return wrapper


def require_csrf() -> None:
    submitted = (request.form.get("csrf_token")
                 or request.headers.get("X-CSRF-Token", ""))
    if not hmac.compare_digest(str(submitted), str(getattr(g, "csrf_token", ""))):
        audit("CSRF_REJECTED", path=request.path)
        abort(403)


def set_session_cookie(response: Response, token: str) -> Response:
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_TTL,
        secure=os.getenv("ADMIN_COOKIE_SECURE", "true").lower() != "false",
        httponly=True, samesite="Strict", path="/",
    )
    return response


# --------------------------------------------------------------------- auth

@app.route("/login", methods=["GET", "POST"])
def login():
    config = load_config()
    if not config:
        return render_template("message.html",
                               title="Not configured",
                               message="Run setup.py to create admin-config.json."), 503

    if not ip_allowed(config):
        audit("LOGIN_BLOCKED_IP")
        abort(403)

    error = None
    if request.method == "POST":
        if login_attempts_exceeded():
            audit("LOGIN_RATE_LIMITED")
            time.sleep(5)
            return render_template(
                "login.html",
                error=f"Too many attempts. Locked out for {LOGIN_WINDOW // 60} minutes.",
            ), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username, str(config.get("username", "")))
        try:
            pass_ok = bcrypt.checkpw(password.encode(),
                                     str(config.get("password_hash", "")).encode())
        except (ValueError, TypeError):
            pass_ok = False

        # Both checks always run, then combine, so timing does not reveal which failed.
        if user_ok and pass_ok:
            # Password alone grants nothing: this ticket only unlocks the TOTP step.
            ticket = secrets.token_hex(32)
            _redis_admin().setex(f"admin:pending:{ticket}", PENDING_TTL,
                                 json.dumps({"user": username, "ip": client_ip()}))
            audit("LOGIN_PASSWORD_OK", attempted_user=username)
            response = redirect(url_for("login_totp"))
            response.set_cookie("sb_pending", ticket, max_age=PENDING_TTL,
                                secure=os.getenv("ADMIN_COOKIE_SECURE", "true").lower() != "false",
                                httponly=True, samesite="Strict", path="/")
            return response

        record_login_failure()
        audit("LOGIN_FAILED", attempted_user=username[:64])
        time.sleep(1)
        error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    config = load_config()
    if not config or not ip_allowed(config):
        abort(403)

    ticket = request.cookies.get("sb_pending")
    if not ticket:
        return redirect(url_for("login"))
    try:
        raw = _redis_admin().get(f"admin:pending:{ticket}")
    except redis.RedisError:
        raw = None
    if not raw:
        return redirect(url_for("login"))

    pending = json.loads(raw)
    if pending.get("ip") != client_ip():
        _redis_admin().delete(f"admin:pending:{ticket}")
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        if login_attempts_exceeded():
            time.sleep(5)
            return render_template("totp.html", error="Too many attempts."), 429

        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(str(config.get("totp_secret", "")))
        if code and totp.verify(code, valid_window=1):
            # Single-use: burn the ticket so a replayed code cannot re-authenticate.
            _redis_admin().delete(f"admin:pending:{ticket}")
            clear_login_failures()
            token = create_session(pending["user"])
            g.admin_user = pending["user"]
            audit("LOGIN_SUCCESS")
            response = redirect(url_for("dashboard"))
            response.delete_cookie("sb_pending")
            return set_session_cookie(response, token)

        record_login_failure()
        g.admin_user = pending["user"]
        audit("TOTP_FAILED")
        time.sleep(1)
        error = "Invalid code."

    return render_template("totp.html", error=error)


@app.route("/logout", methods=["GET", "POST"])
@require_auth
def logout():
    try:
        _redis_admin().delete(f"admin:session:{g.session_token}")
    except redis.RedisError:
        pass
    audit("LOGOUT")
    response = redirect(url_for("login"))
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------------------------------------------------------------- data access

def honeypot_redis_error():
    """None when redis-honeypot answers, otherwise why it does not.

    Worth asking separately, because the identity store being unreachable and
    the identity store being empty produce the same empty page otherwise. That
    is a genuinely confusing failure -- the event feed keeps updating from disk
    while every attacker profile reports "unknown IP", which reads like data
    loss rather than a broken connection.
    """
    try:
        _redis_honeypot().ping()
        return None
    except redis.RedisError as exc:
        return f"{type(exc).__name__}: {exc}"


def iter_identities():
    """Yield (ip_hash, identity dict) for every tracked IP.

    Swallows connection errors so a page still renders; callers that care about
    the difference between "none" and "could not ask" should call
    honeypot_redis_error() first.
    """
    try:
        client = _redis_honeypot()
        for key in client.scan_iter("hp:identity:*", count=200):
            raw = client.get(key)
            if not raw:
                continue
            try:
                yield key.split(":")[-1], json.loads(raw)
            except json.JSONDecodeError:
                continue
    except redis.RedisError:
        return


def safe_ip(value: str) -> str:
    """Reject anything that is not an IP literal.

    These routes are operator-only, but the value reaches a glob pattern and ZIP
    member names, so validate rather than trusting the URL.
    """
    candidate = (value or "").strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        abort(400)
    return candidate


def resolve_identity(ip: str):
    try:
        raw = _redis_honeypot().get(f"hp:identity:{hashlib.md5(ip.encode()).hexdigest()}")
    except redis.RedisError:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def log_files(max_days: int = 7):
    """Event-log files for the newest days, newest day first.

    Counted in days rather than files: a day displaced by the old logrotate
    stanza spans several files, and a flat file count would have silently
    narrowed the live feed's window to two or three days.
    """
    return [path for day in available_days()[:max_days] for path in day_files(day)]


def tail_lines(path: Path, max_bytes: int = 8 * 1024 * 1024) -> list:
    """Return the last max_bytes of a file as lines.

    A single day's log can reach 100MB under a sustained scan; reading one whole
    would blow the container's memory limit. Seek instead and drop the first
    (likely partial) line.
    """
    try:
        if path.suffix == ".gz":
            # No seeking to an offset in a compressed stream, so decompress
            # forward and keep a sliding window of the tail. Held as a list of
            # chunks rather than one buffer that is concatenated and re-sliced
            # every megabyte, which would turn a 100MB archive into gigabytes
            # of copying to read its last 8MB.
            chunks = []
            kept = 0
            partial = False
            with gzip.open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    kept += len(chunk)
                    while chunks and kept - len(chunks[0]) >= max_bytes:
                        kept -= len(chunks.pop(0))
                        partial = True
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                raw = raw[-max_bytes:]
                partial = True
        else:
            size = path.stat().st_size
            with open(path, "rb") as handle:
                if size > max_bytes:
                    handle.seek(size - max_bytes)
                    partial = True
                else:
                    partial = False
                raw = handle.read()
    except (OSError, EOFError, gzip.BadGzipFile):
        return []
    lines = raw.decode("utf-8", "replace").splitlines()
    return lines[1:] if partial and lines else lines


def read_events(limit=200, ip_filter=None, since=None, max_days=7):
    """Read newest-first across daily JSONL files, stopping once limit is met."""
    events = []
    for path in log_files(max_days):
        lines = tail_lines(path)
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ip_filter and event.get("real_ip") != ip_filter:
                continue
            if since and str(event.get("timestamp", "")) <= since:
                continue
            events.append(event)
            if len(events) >= limit:
                return events
    return events


def session_files(ip=None):
    directory = STORAGE_DIR / "sessions"
    if not directory.is_dir():
        return []
    pattern = f"{ip.replace(':', '_')}_*.cast" if ip else "*.cast"
    out = []
    for path in sorted(directory.glob(pattern), reverse=True):
        try:
            stat = path.stat()
        except OSError:
            continue
        # Duration is the offset on the final frame, so only the tail is needed.
        duration = 0.0
        for line in reversed(tail_lines(path, max_bytes=8192)):
            try:
                frame = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(frame, list) and frame:
                try:
                    duration = float(frame[0])
                except (ValueError, TypeError):
                    duration = 0.0
                break
        info = clip_info(path.stem)
        out.append({
            "name": path.name,
            "ip": path.name.split("_")[0],
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            # Prefer the connection's real length; fall back to the span
            # between the first and last write when there is no sidecar.
            "duration": info.get("session_seconds")
            if info.get("session_seconds") is not None else round(duration, 1),
            "write_span": round(duration, 1),
            **info,
        })
    return out


# Idle time between two connections is collapsed to this many seconds of
# playback. Matches the player's own MAX_GAP, so dead air inside a connection
# and dead air between two connections squeeze to the same length.
STITCH_GAP = 2.0


def _read_cast_header(path: Path) -> dict:
    """Just the leading header object, so segments can be ordered cheaply."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                parsed = json.loads(line)
                return parsed if isinstance(parsed, dict) else {}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _read_cast_frames(path: Path, budget: int):
    """Up to `budget` frames from one asciicast v2 file.

    Budgeted by the caller rather than read whole: an attacker with fifty
    connections has a hundred megabytes of recordings, and inflating all of it
    into Python lists at once would exceed this container's memory limit before
    a single frame reached the browser.
    """
    frames = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if len(frames) >= budget:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, list) and len(parsed) >= 3:
                    try:
                        frames.append([float(parsed[0]), str(parsed[1]), str(parsed[2])])
                    except (TypeError, ValueError):
                        continue
    except OSError:
        pass
    return frames


def _human_gap(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def stitch_sessions(ip: str, max_frames: int = 40000):
    """Every recording for one attacker as a single continuous asciicast.

    The honeypot opens a new .cast per TCP connection, which is the right way to
    record it and the wrong way to watch it: an attacker who reconnects nine
    times becomes nine players, and the operator has to reassemble the
    engagement in their head from nine separate start buttons.

    Segments are laid end to end on one clock. The real idle time between
    connections is deliberately NOT preserved -- someone who came back four
    hours later would otherwise leave four hours of dead air in the middle of
    the timeline. Each gap collapses to STITCH_GAP behind a banner naming the
    true interval, so the elapsed time is still readable without being sat
    through. The banner is an ordinary output frame rather than a protocol-level
    marker: the player would need a second frame type to carry one, and this
    way the seam is legible in a plain `cat` of the stitched file too.

    Returns (header, frames, segments); header is None when nothing is recorded.
    """
    directory = STORAGE_DIR / "sessions"
    if not directory.is_dir():
        return None, [], []

    # Headers first. Ordering the segments needs only each file's start time,
    # and reading headers is cheap enough to do for all of them before deciding
    # how much of the frame budget each one gets.
    found = []
    for path in sorted(directory.glob(f"{ip.replace(':', '_')}_*.cast")):
        head = _read_cast_header(path)
        try:
            fallback = path.stat().st_mtime
        except OSError:
            continue
        found.append({
            "path": path,
            "header": head,
            "start": float(head.get("timestamp") or fallback),
            # "1.2.3.4_20260728T091412_ssh.cast" -> "ssh"
            "service": path.stem.rsplit("_", 1)[-1],
        })
    if not found:
        return None, [], []

    found.sort(key=lambda s: s["start"])

    out = []
    segments = []
    base = 0.0
    previous_end = None
    truncated = False
    used = 0

    for position, segment in enumerate(found):
        frames = _read_cast_frames(segment["path"], max_frames - used)
        if not frames:
            # Either empty, or the budget is gone and later segments cannot be
            # shown at all -- which is itself worth saying.
            if used >= max_frames:
                truncated = True
                break
            continue
        used += len(frames)
        duration = frames[-1][0]

        if position and previous_end is not None:
            idle = max(segment["start"] - previous_end, 0)
            started = datetime.fromtimestamp(segment["start"], timezone.utc)
            out.append([round(base, 6), "o",
                        f"\r\n\r\n--- reconnected {started.strftime('%H:%M:%S')} UTC"
                        f" · {segment['service']} · after {_human_gap(idle)} idle ---\r\n\r\n"])
            base += STITCH_GAP

        segments.append({
            "name": segment["path"].name,
            "service": segment["service"],
            "offset": round(base, 1),
            "duration": round(duration, 1),
            "started": datetime.fromtimestamp(segment["start"], timezone.utc).isoformat(),
        })

        for offset, stream, data in frames:
            out.append([round(base + offset, 6), stream, data])

        base += duration
        previous_end = segment["start"] + duration

    if truncated:
        out.append([round(base, 6), "o",
                    f"\r\n\r\n--- playback truncated at {max_frames} frames; "
                    f"the complete recordings are in the evidence export ---\r\n"])

    if not out:
        return None, [], []

    header = {
        "version": 2,
        # The widest segment, so a later wide terminal is not clipped to an
        # earlier narrow one.
        "width": max((s["header"].get("width") or 80) for s in found),
        "height": max((s["header"].get("height") or 24) for s in found),
        "timestamp": int(found[0]["start"]),
        "title": f"{len(segments)} connection(s) from {ip}",
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    return header, out, segments


def clip_info(stem: str) -> dict:
    """Rendered clip and delivery outcome for a recording, if session-cam got to it.

    Read off disk rather than asked for over the network: session-cam sits on an
    egress-only network the dashboard cannot reach, and shares state with the
    rest of the appliance solely through the storage volume.
    """
    info = {"clip": None, "clip_size": 0, "cam_status": "", "cam_detail": "",
            "session_seconds": None}

    # Wall-clock length of the connection. The .cast frame offsets measure only
    # the time between writes, so a `ssh host '<cmd>'` session -- everything
    # happening inside five milliseconds -- reads as 0.0s and tells you nothing
    # about how long the attacker was actually connected.
    meta_path = STORAGE_DIR / "sessions" / f"{stem}.meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("duration") is not None:
                info["session_seconds"] = round(float(meta["duration"]), 1)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    for suffix in (".mp4", ".gif"):
        candidate = CLIP_DIR / f"{stem}{suffix}"
        if candidate.is_file():
            try:
                info["clip"] = candidate.name
                info["clip_size"] = candidate.stat().st_size
            except OSError:
                info["clip"] = None
            break

    marker = STORAGE_DIR / "sessions" / f"{stem}.cam.json"
    if not marker.is_file():
        info["cam_status"] = "pending" if info["clip"] is None else "rendered"
        return info

    try:
        record = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        info["cam_status"] = "unknown"
        return info

    if record.get("error"):
        info["cam_status"] = "error"
        info["cam_detail"] = str(record["error"])
    elif record.get("skipped"):
        info["cam_status"] = "skipped"
        info["cam_detail"] = str(record["skipped"])
    else:
        delivery = record.get("delivery") or {}
        sent = [channel for channel, result in delivery.items() if result == "sent"]
        failed = [f"{channel}: {result}" for channel, result in delivery.items()
                  if result not in ("sent", "not configured")]
        info["cam_status"] = "sent" if sent else ("failed" if failed else "rendered")
        info["cam_detail"] = ", ".join(sent + failed) or "no channels configured"
    return info


def live_holds(ip: str = None):
    """Connections being drained right now.

    Distinct from the tarpit_active flag, which only records that an IP is
    marked for tarpitting. These keys exist for the lifetime of an individual
    held socket and carry a TTL past the maximum hold, so a container that dies
    mid-drain cannot leave a phantom connection on the dashboard.
    """
    pattern = f"hp:holding:{hashlib.md5(ip.encode()).hexdigest()}:*" if ip \
        else "hp:holding:*"
    out = []
    try:
        client = _redis_honeypot()
        for key in client.scan_iter(match=pattern, count=500):
            raw = client.get(key)
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            record["seconds"] = round(time.time() - float(record.get("started", 0)), 1)
            out.append(record)
    except (redis.RedisError, ValueError, TypeError):
        return []
    return sorted(out, key=lambda r: -r.get("seconds", 0))


@app.route("/api/holds")
@require_auth
def api_holds():
    return jsonify(live_holds())


# A recording is in progress when the writer has not written its sidecar yet.
# The .meta.json only appears on close, which makes its absence an exact signal
# rather than a guess -- but a container killed mid-session leaves one absent
# forever, so recency is required too.
LIVE_SESSION_WINDOW = 120


def live_sessions():
    """Recordings still being written to right now.

    Read off the filesystem, like everything else the dashboard knows about
    sessions. There is no socket to the honeypot and no way to send anything
    towards the attacker from here: this observes a file that another container
    happens to be appending to, which is why watching a live session cannot
    become interfering with one.
    """
    directory = STORAGE_DIR / "sessions"
    if not directory.is_dir():
        return []
    now = time.time()
    out = []
    for path in directory.glob("*.cast"):
        if path.with_suffix(".meta.json").exists():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        idle = now - stat.st_mtime
        if idle > LIVE_SESSION_WINDOW:
            continue
        stem = path.stem
        parts = stem.split("_")
        out.append({
            "name": path.name,
            "ip": parts[0] if parts else "unknown",
            "service": parts[-1] if len(parts) > 2 else "",
            "bytes": stat.st_size,
            "idle_seconds": round(idle, 1),
            "started": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
        })
    # Most recently active first: that is the one worth opening.
    return sorted(out, key=lambda s: s["idle_seconds"])


@app.route("/api/sessions/live")
@require_auth
def api_sessions_live():
    return jsonify(live_sessions())


def country_flag(code) -> str:
    """ISO 3166-1 alpha-2 to a flag emoji.

    Built from regional indicator symbols rather than shipped as images: no
    sprite sheet to fetch, which matters on a dashboard reached through an SSH
    tunnel to a box with no egress, and no image set to keep current when a
    country changes its flag.
    """
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code)


def status_of(identity: dict) -> str:
    if identity.get("banned"):
        return "BANNED"
    if identity.get("tarpit_active"):
        return "TARPITTED"
    return "ACTIVE"


# ----------------------------------------------------------------- dashboard

@app.route("/")
@require_auth
def dashboard():
    rows = []
    countries = set()
    for _, identity in iter_identities():
        address = identity.get("ip") or "unknown"
        # geoip caches, so several thousand identities cost a few thousand
        # dictionary hits rather than a few thousand database reads.
        code = (geoip.lookup(address) or {}).get("country_code") or ""
        if code:
            countries.add(code)
        rows.append({
            # Written by both the PHP engine and the Python services.
            "ip": address,
            "first_seen": identity.get("first_seen", ""),
            "last_seen": identity.get("last_seen", ""),
            "score": identity.get("score", 0),
            "services": ", ".join(identity.get("services_touched") or []),
            "tool": identity.get("tool_detected") or "-",
            "status": status_of(identity),
            "country": code,
            "flag": country_flag(code),
        })
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    # Only asked when the list came back empty: a healthy deployment renders
    # this page constantly and does not need a PING every time.
    return render_template("dashboard.html", rows=rows,
                           countries=sorted(countries),
                           redis_error=honeypot_redis_error() if not rows else None,
                           csrf_token=g.csrf_token)


# Wrappers an attacker types before the command that matters. Counting the
# first token blindly would report a top command of "sudo" for a host that ran
# sudo once against five different binaries.
COMMAND_PREFIXES = {"sudo", "doas", "env", "nohup", "time", "exec", "command"}


def loader_iocs(ip: str = None, limit: int = 500):
    """Second-stage retrieval targets recorded from attacker commands.

    Read off the filesystem rather than re-parsed out of the event log: the
    honeypot already did the extraction at the moment it saw the command, and
    storage/ioc/ carries the sighting history and the fetch outcome with it.
    """
    directory = STORAGE_DIR / "ioc"
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json"))[:limit * 2]:
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(entry, dict):
            continue
        sightings = entry.get("sightings") or []
        if ip and not any(s.get("ip") == ip for s in sightings):
            continue
        fetch = entry.get("fetch") or {}
        out.append({
            "url": f"{entry.get('scheme')}://{entry.get('host')}:{entry.get('port')}"
                   f"{entry.get('path')}",
            "host": entry.get("host"),
            "port": entry.get("port"),
            "method": entry.get("method"),
            "public": bool(entry.get("public", True)),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "times_seen": entry.get("times_seen", 0),
            "sources": len({s.get("ip") for s in sightings if s.get("ip")}),
            "fetch_status": fetch.get("status") or "not attempted",
            "fetch_detail": fetch.get("detail") or "",
            "sha256": fetch.get("sha256"),
        })
    out.sort(key=lambda e: str(e.get("last_seen") or ""), reverse=True)
    return out[:limit]


def top_commands(commands, limit: int = 12):
    """The programs this attacker actually invoked, most-used first.

    Counted by executable rather than by whole command line: `cat /etc/passwd`
    and `cat /etc/shadow` are one behaviour worth seeing as "cat (2)", and a
    list of distinct full command lines is just the transcript again.
    """
    counter = Counter()
    for entry in commands:
        payload = (entry.get("payload") or "").strip()
        if not payload:
            continue
        # Take the first pipeline stage; `curl x | sh` is a curl.
        head = re.split(r"[|;&]", payload, 1)[0].strip()
        for token in head.split():
            # Skip leading VAR=value assignments and wrapper commands.
            if "=" in token.split("/")[-1] and not token.startswith("-"):
                continue
            name = token.split("/")[-1]
            if name in COMMAND_PREFIXES:
                continue
            if name.startswith("-"):
                continue
            counter[name[:32]] += 1
            break
    return counter.most_common(limit)


def service_timeline(history, limit: int = 400):
    """Scored events as points on a clock, grouped into per-service lanes.

    Lanes rather than one row of coloured dots: which service an event belongs
    to is then carried by position, so it survives being read by someone who
    cannot separate two hues -- the same reason nothing else on this dashboard
    encodes identity in colour alone.
    """
    points = []
    for entry in history[-limit:]:
        stamp = str(entry.get("timestamp") or "")
        if not stamp:
            continue
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        points.append({
            "t": when.timestamp(),
            "label": when.strftime("%H:%M:%S"),
            "service": entry.get("service") or "web",
            "event": entry.get("event_type") or "",
            "points": float(entry.get("points") or 0),
        })
    points.sort(key=lambda p: p["t"])
    return points


@app.route("/api/ip/<path:ip>/timeline")
@require_auth
def api_ip_timeline(ip):
    ip = safe_ip(ip)
    identity = resolve_identity(ip) or {}
    return jsonify({"points": service_timeline(identity.get("session_history") or [])})


@app.route("/ip/<path:ip>")
@require_auth
def ip_detail(ip):
    ip = safe_ip(ip)
    identity = resolve_identity(ip)
    if identity is None:
        return render_template("message.html", title="Unknown IP",
                               message=f"No identity recorded for {ip}."), 404

    history = identity.get("session_history") or []
    breakdown = defaultdict(lambda: {"count": 0, "points": 0.0})
    for event in history:
        entry = breakdown[event.get("event_type", "UNKNOWN")]
        entry["count"] += 1
        entry["points"] += float(event.get("points") or 0)

    events = read_events(limit=500, ip_filter=ip)
    # Cloudflare's header only exists for proxied web traffic, so it is blank
    # for SSH, telnet, SMB and RDP. GeoIP works from the address alone and
    # covers everything -- when the database is present.
    cf_country = next((e.get("headers", {}).get("cf_ipcountry")
                       for e in events if e.get("headers", {}).get("cf_ipcountry")), None)
    country = geoip.describe(ip, cf_country)

    page = max(1, request.args.get("page", 1, type=int))
    per_page = 50
    start = (page - 1) * per_page

    # Every event carrying a command line, not just WEBSHELL_CMD. Filtering on
    # that one type hid the most interesting entries an attacker produces:
    # DROPPED_BINARY_EXEC, PERSISTENCE_ATTEMPT and FILE_UPLOAD all record what
    # was actually run or written, and none showed up under "commands issued".
    commands = [e for e in history
                if e.get("event_type") in COMMAND_EVENTS
                and (e.get("payload") or "").strip()]

    credentials = identity.get("credentials") or []
    recordings = session_files(ip)

    # Time this address spent held in the tarpit. The closing TARPIT_HELD frame
    # carries the true total; keepalives report elapsed-since-start and summing
    # those counts the same seconds repeatedly.
    wasted = sum(float(e.get("held_seconds") or 0) for e in events
                 if e.get("event_type") == "TARPIT_HELD")

    return render_template(
        "ip_detail.html",
        ip=ip, identity=identity, status=status_of(identity), country=country,
        breakdown=sorted(breakdown.items(), key=lambda kv: -kv[1]["points"]),
        credentials=credentials[-100:],
        commands=commands[-100:],
        top_commands=top_commands(commands),
        usernames=sorted({c.get("username") for c in credentials if c.get("username")}),
        passwords=sorted({c.get("password") for c in credentials if c.get("password")}),
        persistence=sum(1 for e in history
                        if e.get("event_type") == "PERSISTENCE_ATTEMPT"),
        wasted_minutes=round(wasted / 60, 1),
        payloads=[e for e in history
                  if e.get("event_type") in ("SQLI_BASIC", "SQLI_UNION_BLIND", "SQLI_OOB",
                                             "PHP_EVAL_ATTEMPT", "FILE_UPLOAD",
                                             "REVERSE_SHELL")][-100:],
        loaders=loader_iocs(ip),
        timeline=service_timeline(history),
        events=events[start:start + per_page],
        page=page, total_pages=max(1, (len(events) + per_page - 1) // per_page),
        sessions=recordings, csrf_token=g.csrf_token,
    )


@app.route("/sessions")
@require_auth
def sessions():
    return render_template("sessions.html", sessions=session_files(),
                           csrf_token=g.csrf_token)


@app.route("/sessions/<path:name>/raw")
@require_auth
def session_raw(name):
    safe = Path(name).name
    path = STORAGE_DIR / "sessions" / safe
    if not path.is_file() or path.suffix != ".cast":
        abort(404)
    return Response(path.read_text(encoding="utf-8", errors="replace"),
                    mimetype="application/x-asciicast")


@app.route("/sessions/by-ip/<path:ip>/raw")
@require_auth
def session_stitched(ip):
    """One attacker's whole engagement as a single playable recording."""
    ip = safe_ip(ip)
    header, frames, _ = stitch_sessions(ip)
    if header is None:
        abort(404)
    body = "\n".join([json.dumps(header)]
                     + [json.dumps(frame) for frame in frames])
    return Response(body + "\n", mimetype="application/x-asciicast")


@app.route("/api/sessions/<path:ip>/segments")
@require_auth
def api_session_segments(ip):
    """Where each connection begins on the stitched timeline."""
    ip = safe_ip(ip)
    _, _, segments = stitch_sessions(ip)
    return jsonify({"ip": ip, "segments": segments})


@app.route("/clips/<path:name>")
@require_auth
def session_clip(name):
    """Serve a rendered clip. Path(name).name strips any traversal attempt, and
    the suffix allowlist keeps this from becoming a reader for the whole volume."""
    safe = Path(name).name
    if Path(safe).suffix not in (".gif", ".mp4"):
        abort(404)
    path = CLIP_DIR / safe
    if not path.is_file():
        abort(404)

    download = request.args.get("download") == "1"
    if download:
        audit("CLIP_DOWNLOAD", clip=safe)
    return send_file(
        path,
        mimetype="video/mp4" if path.suffix == ".mp4" else "image/gif",
        as_attachment=download,
        download_name=safe,
    )


@app.route("/evidence")
@require_auth
def evidence():
    path = STORAGE_DIR / "evidence" / "fail2ban.log"
    content = ""
    if path.is_file():
        # Tail only: this file can reach 64MB between rotations.
        content = "\n".join(tail_lines(path, max_bytes=512 * 1024))
    return render_template("evidence.html", content=content, csrf_token=g.csrf_token)


@app.route("/api/evidence/download")
@require_auth
def evidence_download():
    path = STORAGE_DIR / "evidence" / "fail2ban.log"
    if not path.is_file():
        abort(404)
    audit("EVIDENCE_DOWNLOAD")
    return send_file(path, as_attachment=True, download_name="fail2ban.log")


@app.route("/stats")
@require_auth
def stats():
    return render_template("stats.html", csrf_token=g.csrf_token)


DAY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl")


def day_files(day: str):
    """Every file holding events for one UTC day, live file first.

    Normally that is the single file the writer appends to. It is a list because
    older deployments ran a logrotate stanza over this tree, and `copytruncate`
    moved finished days into numbered siblings -- 2026-07-28.jsonl.1, then
    .2.gz as later rotations shuffled them along -- while leaving an empty
    2026-07-28.jsonl behind. That stanza is gone (see deploy/logrotate-drosera),
    but the displaced archives are still on disk on every box that ran it, and
    they are recoverable: copytruncate copies the *content* of a file already
    named for its day, so every sibling of 2026-07-28.jsonl* holds 07-28 events
    and nothing else. Reading them back is the whole repair.
    """
    directory = STORAGE_DIR / "logs"
    if not directory.is_dir():
        return []
    live = directory / f"{day}.jsonl"
    rotated = sorted(p for p in directory.glob(f"{day}.jsonl.*") if p.is_file())
    return ([live] if live.is_file() else []) + rotated


def _open_day_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def read_day(day: str, limit: int = 80000):
    """Every event from one UTC day.

    The event log is already one file per day, so daily history needs no extra
    storage and no rollup job -- expiring a day is deleting its file. This reads
    that day directly rather than tailing the most recent few, which is what
    makes an arbitrary past day as cheap to render as today.
    """
    events = []
    paths = day_files(day)
    # Only pay for de-duplication when a day actually spans several files.
    # copytruncate loses writes across the copy/truncate seam rather than
    # duplicating them, but a forced rotation on top of a scheduled one can
    # leave the same lines in two siblings, and double-counting a day is a
    # worse failure than the cost of a set.
    seen = set() if len(paths) > 1 else None

    for path in paths:
        if len(events) >= limit:
            break
        try:
            with _open_day_file(path) as handle:
                for line in handle:
                    if len(events) >= limit:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    if seen is not None:
                        if line in seen:
                            continue
                        seen.add(line)
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        events.append(parsed)
        except (OSError, EOFError, gzip.BadGzipFile):
            # A truncated .gz still yields everything before the damage.
            continue

    if len(paths) > 1:
        # Siblings are read newest-file-first but hold older events, so the
        # merged list is only in order once it is sorted.
        events.sort(key=lambda e: str(e.get("timestamp", "")))
    return events


def available_days():
    directory = STORAGE_DIR / "logs"
    if not directory.is_dir():
        return []
    # Matched on the prefix, not the stem: a day whose only surviving copy is a
    # rotated sibling has a stem of "2026-07-28.jsonl" and would otherwise drop
    # out of the picker entirely.
    days = set()
    for path in directory.glob("*.jsonl*"):
        match = DAY_RE.match(path.name)
        if match:
            days.add(match.group(1))
    return sorted(days, reverse=True)


@app.route("/api/stats")
@require_auth
def api_stats():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day = request.args.get("day", today)
    # Path component, so validate rather than trust: this becomes a filename.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day or ""):
        day = today

    cache_key = f"admin:stats:v3:{day}"
    try:
        cached = _redis_admin().get(cache_key)
        if cached:
            return Response(cached, mimetype="application/json")
    except redis.RedisError:
        pass

    events = read_day(day)

    hourly = Counter()
    by_service = Counter()
    tools = Counter()
    countries = Counter()
    events_by_ip = Counter()
    usernames = Counter()
    passwords = Counter()
    event_types = Counter()
    tarpit_seconds = 0.0

    # Every figure is derived from that day's events rather than from Redis,
    # so a past day reads the same way today does. Redis holds current state
    # only -- it cannot tell you what Tuesday looked like.
    seen_ips = set()
    banned_ips = set()
    tarpitted_ips = set()
    peak_score = {}
    tool_by_ip = {}
    services_by_ip = {}

    for event in events:
        stamp = str(event.get("timestamp", ""))
        if len(stamp) >= 13:
            hourly[stamp[11:13]] += 1

        kind = event.get("event_type")
        if kind:
            event_types[kind] += 1
        if kind == "CREDENTIAL_ATTEMPT":
            # Producers write the pair as "user:pass" into the payload excerpt.
            # Split on the FIRST colon only: a password containing one is
            # ordinary, a username containing one is not.
            excerpt = str(event.get("payload_excerpt") or "")
            if ":" in excerpt:
                user, _, secret = excerpt.partition(":")
                if user:
                    usernames[user[:64]] += 1
                if secret:
                    passwords[secret[:64]] += 1

        address = event.get("real_ip")
        if address:
            events_by_ip[address] += 1
            seen_ips.add(address)
            score = float(event.get("cumulative_score") or 0)
            if score > peak_score.get(address, 0):
                peak_score[address] = score
            if event.get("tool_detected"):
                tool_by_ip[address] = event["tool_detected"]
            if event.get("service"):
                services_by_ip.setdefault(address, set()).add(event["service"])

        if kind == "BAN" and address:
            banned_ips.add(address)
        elif kind == "TARPIT_ENGAGED" and address:
            tarpitted_ips.add(address)

        if event.get("service"):
            by_service[event["service"]] += 1
        if event.get("tool_detected"):
            tools[event["tool_detected"]] += 1
        # TARPIT_HELD only. Keepalives report elapsed-since-start, so a
        # ten-minute hold emits 10, 20, 30 ... 600 and summing them counts the
        # same seconds over and over -- an error that grows with the square of
        # the duration, and produced 64 days of "wasted time" in a single day.
        # The closing TARPIT_HELD already carries the true total.
        if kind == "TARPIT_HELD":
            tarpit_seconds += float(event.get("held_seconds") or 0)

    # Counted per distinct IP rather than per event, so one noisy scanner does
    # not make its country look like a campaign.
    origins = {}
    country_of = {}
    for address in seen_ips:
        record = geoip.lookup(address)
        code = (record or {}).get("country_code")
        country_of[address] = code
        countries[code or "unknown"] += 1
        if not record or record.get("lat") is None:
            continue
        # Grouped by city where GeoIP knows one, and plotted at that city's real
        # coordinates. Rounding to whole degrees was doing the grouping before,
        # which is ~111km: it merged neighbouring cities into one dot and then
        # drew it up to 55km from either of them, so the map looked approximate
        # everywhere and simply wrong in dense regions like the Randstad or the
        # US northeast. Falling back to a tenth of a degree (~11km) keeps the
        # no-city case from becoming a hundred overlapping dots.
        city = record.get("city")
        lat, lon = float(record["lat"]), float(record["lon"])
        key = (city, code) if city else (round(lat, 1), round(lon, 1))
        bucket = origins.setdefault(key, {
            "lat": lat, "lon": lon, "count": 0,
            "label": f"{city}, {code}" if city and code
                     else (city or record.get("country") or code or "?"),
        })
        bucket["count"] += 1

    buckets = Counter()
    for score in peak_score.values():
        buckets[min(int(score // 10) * 10, 60)] += 1

    top = sorted(peak_score.items(), key=lambda kv: -kv[1])[:10]
    identities = [{
        "ip": address,
        "score": round(score, 1),
        "tool_detected": tool_by_ip.get(address),
        "banned": address in banned_ips,
        "tarpit_active": address in tarpitted_ips,
        "services_touched": sorted(services_by_ip.get(address, [])),
    } for address, score in top]

    # Volume and score answer different questions. The highest scorer is the one
    # that did the most alarming thing; the highest-volume host is the one that
    # made the most noise, and a hammering scanner can stay well under the score
    # threshold all day. Both belong on the page.
    noisiest = [{
        "ip": address,
        "events": count,
        "country": country_of.get(address) or "-",
        "flag": country_flag(country_of.get(address)),
        "score": round(peak_score.get(address, 0), 1),
        "status": status_of({"banned": address in banned_ips,
                             "tarpit_active": address in tarpitted_ips}),
    } for address, count in events_by_ip.most_common(10)]

    busiest_hour = max(hourly.items(), key=lambda kv: kv[1])[0] if hourly else None
    # "unknown" is an absence of GeoIP, not a country, so it must never be
    # announced as the top one.
    ranked_countries = [(code, n) for code, n in countries.most_common()
                        if code and code != "unknown"]

    payload = {
        "day": day,
        "is_today": day == today,
        "available_days": available_days(),
        "total_ips": len(seen_ips),
        "active_today": len(seen_ips),
        "banned_total": len(banned_ips),
        "tarpitted_total": len(tarpitted_ips),
        "events_today": len(events),
        "attacker_minutes_wasted": round(tarpit_seconds / 60, 1),
        "hourly": [{"hour": f"{h:02d}", "count": hourly.get(f"{h:02d}", 0)}
                   for h in range(24)],
        "by_service": [{"service": k, "count": v} for k, v in by_service.most_common(12)],
        "tools": [{"tool": k, "count": v} for k, v in tools.most_common(10)],
        "geoip": geoip.available(),
        # Flag alongside the code, not instead of it. A flag is quick to
        # recognise and impossible to search for or read aloud, so the two-letter
        # code stays as the label and the flag decorates it.
        "countries": [{"country": k, "flag": country_flag(k), "count": v}
                      for k, v in countries.most_common(10)],
        # Capped: past a couple of hundred dots the map is a smear, and the
        # busiest origins are the ones worth seeing anyway.
        "origins": sorted(origins.values(), key=lambda o: -o["count"])[:200],
        "score_distribution": [{"bucket": f"{b}-{b + 9}", "count": buckets[b]}
                               for b in sorted(buckets)],
        "top_ips": [{"ip": i.get("ip") or "unknown",
                     "score": i.get("score", 0),
                     "tool": i.get("tool_detected") or "-",
                     "status": status_of(i),
                     "services": ", ".join(i.get("services_touched") or [])}
                    for i in identities],
        "noisiest_ips": noisiest,
        # Headline single values, resolved server-side so the page does not have
        # to re-derive "the largest of these" in three different places.
        "top_ip": noisiest[0]["ip"] if noisiest else None,
        "top_ip_events": noisiest[0]["events"] if noisiest else 0,
        "top_country": (f"{country_flag(ranked_countries[0][0])} "
                        f"{ranked_countries[0][0]}").strip()
                       if ranked_countries else None,
        "top_country_ips": ranked_countries[0][1] if ranked_countries else 0,
        # Excludes the "unknown" bucket, which the Countries tile used to count
        # as a country of its own -- so a day of pure un-geolocated traffic
        # reported "1 country" next to a Top country of "—".
        "countries_total": len(ranked_countries),
        "top_service": by_service.most_common(1)[0][0] if by_service else None,
        "top_service_events": by_service.most_common(1)[0][1] if by_service else 0,
        "busiest_hour": busiest_hour,
        "busiest_hour_events": hourly.get(busiest_hour, 0) if busiest_hour else 0,
        "credential_attempts": event_types.get("CREDENTIAL_ATTEMPT", 0),
        # Totals alongside the top ten, because the length of a list capped at
        # ten is not the number of distinct values and must not be shown as it.
        "distinct_usernames": len(usernames),
        "distinct_passwords": len(passwords),
        "usernames": [{"label": k, "count": v} for k, v in usernames.most_common(10)],
        "passwords": [{"label": k, "count": v} for k, v in passwords.most_common(10)],
        "event_types": [{"type": k, "count": v} for k, v in event_types.most_common(12)],
    }
    body = json.dumps(payload, default=str)
    try:
        # A finished day never changes, so there is no reason to recompute it
        # every thirty seconds for as long as someone keeps looking at it.
        ttl = STATS_CACHE_TTL if day == today else 3600
        _redis_admin().setex(cache_key, ttl, body)
    except redis.RedisError:
        pass
    return Response(body, mimetype="application/json")




# Cap on the addresses carried in a day's facts. Only ever used to union days
# into a lifetime distinct count -- the lists never leave this module.
DAY_IP_CAP = 50000


def day_facts(day: str, today: str):
    """One day reduced to the facts every other view is built from.

    Parsed properly rather than pattern-matched. An earlier version counted
    lines and pulled the address out with a regex, which is much faster but can
    only answer questions a substring can answer -- it could not tell a BAN
    event from a payload that merely mentions the word, and a headline number
    that is quietly wrong is worse than no number.

    Paying for a real parse is affordable because it happens once: a finished
    day never changes, so it is cached for a week and the cost is one scan per
    day per box however often the pages are opened.

    Carries the day's addresses, not just how many, because a lifetime distinct
    count is a union across days and cannot be recovered from per-day totals.
    """
    # v2: v1 was computed through read_day()'s 80,000-event cap and under-reports
    # any day that crossed it. Bumping the key discards those rather than
    # serving them for the rest of their week-long TTL.
    cache_key = f"admin:facts:v2:{day}"
    try:
        cached = _redis_admin().get(cache_key)
        if cached:
            return json.loads(cached)
    except (redis.RedisError, json.JSONDecodeError):
        pass

    # Streamed rather than read_day(), which caps at 80,000 events to bound the
    # memory a page render can take. That cap is right for a page and wrong
    # here: a busy day crossing it would silently under-report every lifetime
    # figure with nothing on screen to say so. Only the sets are held, so there
    # is no ceiling to hit -- the totals are the whole day or they are wrong.
    addresses = set()
    banned = set()
    tarpitted = set()
    tarpit_seconds = 0.0
    total = 0

    for path in day_files(day):
        try:
            with _open_day_file(path) as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(event, dict):
                        continue

                    total += 1
                    address = event.get("real_ip")
                    if address and len(addresses) < DAY_IP_CAP:
                        addresses.add(address)
                    kind = event.get("event_type")
                    if kind == "BAN" and address:
                        banned.add(address)
                    elif kind == "TARPIT_ENGAGED" and address:
                        tarpitted.add(address)
                    # Closing frame only. The web tarpit reports its progress as
                    # TARPIT_KEEPALIVE and only its final frame as TARPIT_HELD,
                    # so counting this type alone counts each connection once.
                    elif kind == "TARPIT_HELD":
                        tarpit_seconds += float(event.get("held_seconds") or 0)
        except (OSError, EOFError, gzip.BadGzipFile):
            continue

    facts = {
        "day": day,
        "events": total,
        "ips": len(addresses),
        "banned": len(banned),
        "tarpitted": len(tarpitted),
        "minutes_wasted": round(tarpit_seconds / 60, 1),
        "ip_list": sorted(addresses),
        "banned_list": sorted(banned),
    }
    try:
        _redis_admin().setex(cache_key,
                             STATS_CACHE_TTL if day == today else 7 * 86400,
                             json.dumps(facts))
    except redis.RedisError:
        pass
    return facts


def lifetime_stats(max_days: int = 400):
    """Every retained day folded into one all-time picture.

    Distinct counts are unions of the per-day address lists, so an address that
    came back on six days counts once -- summing the daily figures would report
    six attackers where there was one, and that error grows with the retention
    window rather than staying constant.
    """
    cache_key = "admin:lifetime:v2"
    try:
        cached = _redis_admin().get(cache_key)
        if cached:
            return json.loads(cached)
    except (redis.RedisError, json.JSONDecodeError):
        pass

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    days = available_days()[:max_days]

    addresses = set()
    banned = set()
    events = 0
    minutes = 0.0
    busiest = {"day": None, "events": 0}

    for day in days:
        facts = day_facts(day, today)
        addresses.update(facts.get("ip_list") or [])
        banned.update(facts.get("banned_list") or [])
        events += facts.get("events", 0)
        minutes += facts.get("minutes_wasted", 0)
        if facts.get("events", 0) > busiest["events"]:
            busiest = {"day": day, "events": facts["events"]}

    countries = Counter()
    for address in addresses:
        record = geoip.lookup(address)
        code = (record or {}).get("country_code")
        if code:
            countries[code] += 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days_observed": len(days),
        "first_day": days[-1] if days else None,
        "last_day": days[0] if days else None,
        "unique_ips": len(addresses),
        "ips_blocked": len(banned),
        "events": events,
        "minutes_wasted": round(minutes, 1),
        "countries": len(countries),
        "busiest_day": busiest["day"],
        "busiest_day_events": busiest["events"],
        "top_countries": [{"country": code, "ips": n}
                          for code, n in countries.most_common(10)],
    }
    try:
        # Short: today's contribution is still moving. The per-day facts under
        # it are what is actually expensive, and those stay cached for a week.
        _redis_admin().setex(cache_key, 300, json.dumps(payload))
    except redis.RedisError:
        pass
    return payload


@app.route("/api/stats/lifetime")
@require_auth
def api_stats_lifetime():
    return jsonify(lifetime_stats())


@app.route("/api/stats/trend")
@require_auth
def api_stats_trend():
    """Per-day totals across the retained history.

    The point of the day picker is comparison, and comparison needs a shape --
    one day at a time tells you nothing about whether today is busy.
    """
    days = min(max(request.args.get("days", 30, type=int) or 30, 2), 90)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # available_days() is newest-first; the chart reads left to right in time.
    wanted = list(reversed(available_days()[:days]))
    # Counts only. day_facts carries each day's addresses so lifetime can union
    # them, and a chart of thirty points has no use for fifty thousand of them.
    return jsonify({"days": [
        {key: value for key, value in day_facts(day, today).items()
         if not key.endswith("_list")}
        for day in wanted
    ]})


@app.route("/api/events")
@require_auth
def api_events():
    limit = min(request.args.get("n", 50, type=int), 500)
    since = request.args.get("since")
    return jsonify(read_events(limit=limit, since=since))


@app.route("/api/ban/<path:ip>", methods=["POST"])
@require_auth
def api_ban(ip):
    require_csrf()
    ip = safe_ip(ip)
    digest = hashlib.md5(ip.encode()).hexdigest()
    try:
        client = _redis_honeypot()
        client.setex(f"hp:banned:{digest}", BAN_TTL, "1")
        raw = client.get(f"hp:identity:{digest}")
        if raw:
            identity = json.loads(raw)
            identity["banned"] = True
            identity["rickroll"] = True
            client.set(f"hp:identity:{digest}", json.dumps(identity), ex=7 * 24 * 3600)
    except (redis.RedisError, json.JSONDecodeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = (f"[{stamp}] HONEYPOT_BAN ip={ip} score=manual reason=OPERATOR_BAN "
            f"tool=none services=manual\n")
    try:
        evidence_path = STORAGE_DIR / "evidence" / "fail2ban.log"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass

    audit("MANUAL_BAN", target_ip=ip)
    return jsonify({"ok": True, "ip": ip, "banned": True})


@app.route("/api/unban/<path:ip>", methods=["POST"])
@require_auth
def api_unban(ip):
    require_csrf()
    ip = safe_ip(ip)
    digest = hashlib.md5(ip.encode()).hexdigest()
    try:
        client = _redis_honeypot()
        client.delete(f"hp:banned:{digest}")
        raw = client.get(f"hp:identity:{digest}")
        if raw:
            identity = json.loads(raw)
            identity["banned"] = False
            identity["rickroll"] = False
            client.set(f"hp:identity:{digest}", json.dumps(identity), ex=7 * 24 * 3600)
    except (redis.RedisError, json.JSONDecodeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    audit("MANUAL_UNBAN", target_ip=ip)
    return jsonify({"ok": True, "ip": ip, "banned": False})


def _set_tarpit(ip: str, active: bool):
    """Flip the tarpit flag on a stored identity.

    Separate from banning on purpose, and the more useful of the two: a ban
    closes the connection immediately, which costs the attacker nothing. The
    tarpit is what actually spends their time, so being able to put someone
    back into it -- or let a false positive out -- is the control that matters.
    """
    digest = hashlib.md5(ip.encode()).hexdigest()
    try:
        client = _redis_honeypot()
        raw = client.get(f"hp:identity:{digest}")
        if not raw:
            return jsonify({"ok": False,
                            "error": "no identity recorded for that address"}), 404
        identity = json.loads(raw)
        identity["tarpit_active"] = active
        client.set(f"hp:identity:{digest}", json.dumps(identity), ex=7 * 24 * 3600)
    except (redis.RedisError, json.JSONDecodeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    audit("MANUAL_TARPIT" if active else "MANUAL_UNTARPIT", target_ip=ip)
    return jsonify({"ok": True, "ip": ip, "tarpit_active": active})


@app.route("/api/tarpit/<path:ip>", methods=["POST"])
@require_auth
def api_tarpit(ip):
    require_csrf()
    return _set_tarpit(safe_ip(ip), True)


@app.route("/api/untarpit/<path:ip>", methods=["POST"])
@require_auth
def api_untarpit(ip):
    require_csrf()
    return _set_tarpit(safe_ip(ip), False)


EXPORT_CHUNK = 256 * 1024


class _ZipStream:
    """Unseekable sink, so an archive can be sent without ever being stored.

    This container has a 384MB memory limit and a 64MB tmpfs, while the storage
    tree it exports can reach several gigabytes of recordings and clips. There
    is therefore nowhere to put a finished bulk archive -- not in RAM, not on
    disk -- so it is generated and streamed a chunk at a time instead. zipfile
    falls back to data descriptors when the underlying stream reports itself
    unseekable, which produces exactly the streamable format this needs.
    """

    def __init__(self):
        self._buffer = bytearray()
        self._position = 0

    def write(self, data):
        self._buffer += data
        self._position += len(data)
        return len(data)

    def tell(self):
        return self._position

    def flush(self):
        pass

    def seekable(self):
        return False

    def drain(self) -> bytes:
        chunk = bytes(self._buffer)
        del self._buffer[:]
        return chunk


def _stream_archive(build):
    """Drive a bundle generator, flushing whatever the ZIP has produced.

    Wrapped in stream_with_context by the callers: a streamed response is
    consumed after the request context would normally have been torn down, and
    the Redis handles these bundles read from are cached on `g`.
    """
    stream = _ZipStream()
    archive = zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED)
    try:
        for _ in build(archive):
            chunk = stream.drain()
            if chunk:
                yield chunk
    finally:
        archive.close()
    yield stream.drain()


def _add_bytes(archive, arcname: str, data, ledger: list):
    if isinstance(data, str):
        data = data.encode("utf-8")
    archive.writestr(arcname, data)
    ledger.append((arcname, hashlib.sha256(data).hexdigest(), len(data)))


def _add_file(archive, path: Path, arcname: str, ledger: list):
    """Copy a file in, hashing as it goes and yielding between chunks.

    Chunked rather than archive.write(): a 400MB clip written in one call would
    inflate the stream buffer to 400MB, which is the exact failure streaming is
    here to avoid.
    """
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as source, archive.open(arcname, "w") as target:
            while True:
                block = source.read(EXPORT_CHUNK)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                target.write(block)
                yield
    except (OSError, ValueError):
        return
    ledger.append((arcname, digest.hexdigest(), size))


def loot_index():
    """sha256 -> (metadata, set of IPs that dropped it)."""
    directory = STORAGE_DIR / "loot"
    index = {}
    if not directory.is_dir():
        return index
    for meta_path in sorted(directory.glob("*.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        digest = meta.get("sha256") or meta_path.stem
        addresses = {s.get("ip") for s in (meta.get("sightings") or []) if s.get("ip")}
        index[digest] = (meta, addresses)
    return index


BULK_EVENT_BUDGET = 150000


def events_for(addresses, max_days: int = 90, per_ip: int = 2000,
               budget: int = BULK_EVENT_BUDGET):
    """One pass over the retained log, bucketed by address.

    A bulk export would otherwise re-read every retained day once per attacker:
    O(attackers x days) file reads to answer what a single pass answers. Bounded
    twice over -- per address and in total -- because this runs inside a 384MB
    container against a log that has no such limit. Days are walked newest-first
    so that hitting a bound costs the oldest history rather than the freshest.
    """
    wanted = {address for address in addresses if address}
    out = {address: [] for address in wanted}
    if not wanted:
        return out

    held = 0
    for day in available_days()[:max_days]:
        if held >= budget:
            break
        for event in read_day(day):
            address = event.get("real_ip")
            if address not in wanted:
                continue
            bucket = out[address]
            if len(bucket) >= per_ip:
                continue
            bucket.append(event)
            held += 1
            if held >= budget:
                break

    for bucket in out.values():
        bucket.sort(key=lambda e: str(e.get("timestamp", "")))
    return out


def ban_log_index():
    """IP -> its lines from the fail2ban evidence log.

    Read once and bucketed: a bulk export would otherwise scan the whole ban
    log once per attacker. The file is the record the firewall actually acted
    on, so an attacker's own lines belong in their bundle -- an abuse report
    that shows what was observed but not what was done about it is half a
    report.
    """
    index = defaultdict(list)
    path = STORAGE_DIR / "evidence" / "fail2ban.log"
    if not path.is_file():
        return index
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.search(r"\bip=(\S+)", line)
                if match:
                    index[match.group(1)].append(line.rstrip("\n"))
    except OSError:
        pass
    return index


def commands_from(identity, events):
    """Every command line this attacker ran, from both places they are recorded.

    The identity's session_history is capped and lives in Redis under a TTL, so
    on its own it silently loses the early part of a long engagement. The event
    log is the durable copy. Merged and de-duplicated on (timestamp, payload),
    since the same command legitimately appears in both.
    """
    rows = []
    seen = set()
    for entry in (identity or {}).get("session_history") or []:
        if entry.get("event_type") not in COMMAND_EVENTS:
            continue
        payload = (entry.get("payload") or "").strip()
        if not payload:
            continue
        key = (str(entry.get("timestamp", "")), payload)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"timestamp": entry.get("timestamp", ""),
                     "event_type": entry.get("event_type", ""),
                     "service": entry.get("service", ""),
                     "payload": payload})
    for event in events:
        if event.get("event_type") not in COMMAND_EVENTS:
            continue
        payload = (event.get("payload_excerpt") or "").strip()
        if not payload:
            continue
        key = (str(event.get("timestamp", "")), payload)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"timestamp": event.get("timestamp", ""),
                     "event_type": event.get("event_type", ""),
                     "service": event.get("service", ""),
                     "payload": payload})
    rows.sort(key=lambda r: str(r["timestamp"]))
    return rows


def _commands_csv(rows) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["timestamp", "service", "event_type", "command"])
    for row in rows:
        writer.writerow([row["timestamp"], row["service"],
                         row["event_type"], row["payload"]])
    return out.getvalue()


def _credentials_csv(identity) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["timestamp", "service", "username", "password"])
    for cred in (identity or {}).get("credentials") or []:
        writer.writerow([cred.get("timestamp", ""), cred.get("service", ""),
                         cred.get("username", ""), cred.get("password", "")])
    return out.getvalue()


def _attacker_bundle(archive, ip: str, root: str, ledger: list, loot, events,
                     identity=None, ban_lines=None):
    """Everything held on one attacker. A generator: yields between files."""
    if identity is None:
        identity = resolve_identity(ip)

    _add_bytes(archive, f"{root}report.html",
               _report_html(ip, identity, events), ledger)
    yield
    _add_bytes(archive, f"{root}events.jsonl",
               "\n".join(json.dumps(e, default=str) for e in events), ledger)
    yield

    # This address's slice of the ban log: what the firewall was told to do and
    # when. Present even when empty, so its absence reads as "never banned"
    # rather than "the export forgot".
    _add_bytes(archive, f"{root}fail2ban.log",
               ("\n".join(ban_lines) + "\n") if ban_lines
               else f"# No ban lines recorded for {ip}.\n", ledger)
    yield

    # Retrieval targets. On a no-egress deployment this is usually the most
    # actionable thing in the bundle: the sample never arrived, but the address
    # serving it did, and that is what an abuse report can act on.
    loaders = loader_iocs(ip)
    if loaders:
        rows = io.StringIO()
        writer = csv.writer(rows)
        writer.writerow(["url", "host", "port", "method", "times_seen",
                         "first_seen", "last_seen", "fetch_status", "sha256"])
        for row in loaders:
            writer.writerow([row["url"], row["host"], row["port"], row["method"],
                             row["times_seen"], row["first_seen"], row["last_seen"],
                             row["fetch_status"], row["sha256"] or ""])
        _add_bytes(archive, f"{root}loaders.csv", rows.getvalue(), ledger)
        yield

    commands = commands_from(identity, events)
    if commands:
        _add_bytes(archive, f"{root}commands.txt", "\n".join(
            f"[{row['timestamp']}] <{row['event_type']}>"
            f"{(' ' + row['service']) if row['service'] else ''} {row['payload']}"
            for row in commands) + "\n", ledger)
        yield
        # CSV as well as the transcript: one is for reading, the other is for
        # sorting and pivoting, and an analyst should not have to reparse the
        # first to get the second.
        _add_bytes(archive, f"{root}commands.csv", _commands_csv(commands), ledger)
        yield

    if identity:
        _add_bytes(archive, f"{root}identity.json",
                   json.dumps(identity, indent=2, default=str), ledger)
        yield
        _add_bytes(archive, f"{root}credentials.csv",
                   _credentials_csv(identity), ledger)
        yield

    # The engagement as one playable file, alongside the per-connection
    # originals. The originals are the evidence; the stitch is what makes it
    # watchable, and a reviewer who has neither the dashboard nor a way to
    # concatenate nine recordings by hand needs both in the bundle.
    header, frames, segments = stitch_sessions(ip)
    if header is not None:
        _add_bytes(archive, f"{root}sessions/engagement.cast",
                   "\n".join([json.dumps(header)]
                             + [json.dumps(f) for f in frames]) + "\n", ledger)
        yield
        _add_bytes(archive, f"{root}sessions/engagement-index.json",
                   json.dumps(segments, indent=2), ledger)
        yield

    for meta in session_files(ip):
        cast = STORAGE_DIR / "sessions" / meta["name"]
        if cast.is_file():
            for _ in _add_file(archive, cast, f"{root}sessions/{meta['name']}", ledger):
                yield
        sidecar = STORAGE_DIR / "sessions" / f"{cast.stem}.meta.json"
        if sidecar.is_file():
            for _ in _add_file(archive, sidecar, f"{root}sessions/{sidecar.name}", ledger):
                yield
        # The rendered clip: the thing an operator actually shows somebody.
        if meta.get("clip"):
            clip = CLIP_DIR / Path(meta["clip"]).name
            if clip.is_file():
                for _ in _add_file(archive, clip, f"{root}clips/{clip.name}", ledger):
                    yield

    for digest, (meta, addresses) in loot.items():
        if ip not in addresses:
            continue
        blob = STORAGE_DIR / "loot" / f"{digest}.bin"
        if blob.is_file():
            for _ in _add_file(archive, blob, f"{root}loot/{digest}.bin", ledger):
                yield
        _add_bytes(archive, f"{root}loot/{digest}.json",
                   json.dumps(meta, indent=2, default=str), ledger)
        yield

    _add_bytes(archive, f"{root}suggested-fail2ban.txt",
               f"# Add to your jail or run directly:\n"
               f"fail2ban-client set honeypot banip {ip}\n"
               f"ufw insert 1 deny from {ip} to any\n", ledger)
    yield


def _manifest(ledger, subject: str) -> str:
    lines = [
        "Drosera evidence bundle",
        f"Subject:   {subject}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "Every file in this archive with its SHA-256, so the bundle can be shown",
        "intact later. Verify with:  sha256sum -c MANIFEST-SHA256.txt",
        "",
    ]
    lines += [f"{digest}  {name}" for name, digest, _ in ledger]
    lines += ["", f"{len(ledger)} files, "
                  f"{sum(size for _, _, size in ledger)} bytes uncompressed."]
    return "\n".join(lines) + "\n"


@app.route("/api/export/<path:ip>", methods=["POST", "GET"])
@require_auth
def api_export(ip):
    if request.method == "POST":
        require_csrf()
    ip = safe_ip(ip)
    loot = loot_index()
    # A single subject gets a far larger per-address budget than a bulk run:
    # this is the bundle that goes to an abuse desk or a lawyer, and it should
    # be the complete record of that address, not a sample of it.
    events = events_for([ip], per_ip=20000, budget=20000).get(ip, [])
    bans = ban_log_index().get(ip, [])

    def build(archive):
        ledger = []
        for _ in _attacker_bundle(archive, ip, f"{ip}/", ledger, loot, events,
                                  ban_lines=bans):
            yield
        _add_bytes(archive, "MANIFEST-SHA256.txt", _manifest(ledger, ip), [])
        yield

    audit("EVIDENCE_EXPORT", target_ip=ip)
    name = f"evidence-{ip.replace(':', '_')}.zip"
    return Response(stream_with_context(_stream_archive(build)),
                    mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.route("/api/export-bulk", methods=["POST", "GET"])
@require_auth
def api_export_bulk():
    """Every attacker in one archive, streamed.

    Optionally narrowed by score, which is the filter that matters: a honeypot
    accumulates thousands of addresses that knocked once, and a bundle of all of
    them buries the handful worth reading.
    """
    if request.method == "POST":
        require_csrf()

    minimum = request.args.get("min_score", 0, type=float) or 0
    targets = []
    for _, identity in iter_identities():
        address = identity.get("ip")
        if not address:
            continue
        if float(identity.get("score") or 0) < minimum:
            continue
        targets.append((address, identity))
    targets.sort(key=lambda pair: -float(pair[1].get("score") or 0))

    loot = loot_index()
    generated = datetime.now(timezone.utc)
    buckets = events_for([address for address, _ in targets])
    bans = ban_log_index()

    def build(archive):
        ledger = []
        rows = io.StringIO()
        index = csv.writer(rows)
        index.writerow(["ip", "score", "status", "first_seen", "last_seen",
                        "tool", "services", "events_included"])
        for address, identity in targets:
            events = buckets.get(address, [])
            index.writerow([
                address,
                identity.get("score", 0),
                status_of(identity),
                identity.get("first_seen", ""),
                identity.get("last_seen", ""),
                identity.get("tool_detected") or "",
                " ".join(identity.get("services_touched") or []),
                len(events),
            ])
            for _ in _attacker_bundle(archive, address,
                                      f"attackers/{address.replace(':', '_')}/",
                                      ledger, loot, events, identity,
                                      bans.get(address, [])):
                yield

        _add_bytes(archive, "index.csv", rows.getvalue(), ledger)
        yield
        # The fail2ban log is the record the firewall actually acted on, so it
        # belongs in a bundle that claims to be the whole picture.
        evidence_log = STORAGE_DIR / "evidence" / "fail2ban.log"
        if evidence_log.is_file():
            for _ in _add_file(archive, evidence_log, "fail2ban.log", ledger):
                yield
        _add_bytes(archive, "README.txt",
                   f"Drosera bulk evidence export\n"
                   f"Generated: {generated.isoformat()}\n"
                   f"Attackers: {len(targets)}"
                   f"{f' (score >= {minimum:g})' if minimum else ''}\n\n"
                   f"attackers/<ip>/  one complete bundle per address\n"
                   f"index.csv        every address with score and status\n"
                   f"fail2ban.log     the ban record the firewall acted on\n\n"
                   f"All interaction was with emulated services. No real system\n"
                   f"was accessed and no captured credential was ever validated.\n",
                   ledger)
        yield
        _add_bytes(archive, "MANIFEST-SHA256.txt",
                   _manifest(ledger, f"{len(targets)} attackers"), [])
        yield

    audit("EVIDENCE_EXPORT_BULK", attacker_count=len(targets), min_score=minimum)
    name = f"evidence-bulk-{generated.strftime('%Y%m%dT%H%M%SZ')}.zip"
    return Response(stream_with_context(_stream_archive(build)),
                    mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _report_html(ip, identity, events) -> str:
    identity = identity or {}
    breakdown = defaultdict(lambda: {"count": 0, "points": 0.0})
    for event in identity.get("session_history") or []:
        entry = breakdown[event.get("event_type", "UNKNOWN")]
        entry["count"] += 1
        entry["points"] += float(event.get("points") or 0)

    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{data['count']}</td><td>{data['points']:.0f}</td></tr>"
        for name, data in sorted(breakdown.items(), key=lambda kv: -kv[1]["points"])
    )
    creds = "".join(
        f"<tr><td>{_esc(c.get('service'))}</td><td>{_esc(c.get('username'))}</td>"
        f"<td>{_esc(c.get('password'))}</td><td>{_esc(c.get('timestamp'))}</td></tr>"
        for c in (identity.get("credentials") or [])[:200]
    )

    commands = commands_from(identity, events)
    ranked = "".join(f"<li><code>{_esc(name)}</code> &times; {count}</li>"
                     for name, count in top_commands(commands))
    transcript = "\n".join(
        f"[{row['timestamp']}] <{row['event_type']}> {row['payload']}"
        for row in commands[:500])
    # Assembled here rather than inline in the template below: a conditional
    # nested f-string inside a triple-quoted one parses, but it is the kind of
    # line that breaks silently on a quoting change nobody reviews closely.
    ranked_block = (f'<ul class="ranked">{ranked}</ul>' if ranked
                    else "<p>None recorded.</p>")
    transcript_block = f"<pre>{_esc(transcript)}</pre>" if transcript else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Evidence report {_esc(ip)}</title>
<style>body{{font-family:sans-serif;margin:2rem;color:#111;max-width:60rem}}
table{{border-collapse:collapse;margin:1rem 0;width:100%}}
th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:.9rem}}
th{{background:#eee}}h1{{border-bottom:3px solid #333;padding-bottom:.4rem}}
code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace}}
pre{{background:#f6f6f6;border:1px solid #ddd;padding:.8rem;overflow:auto;
max-height:40rem;font-size:.8rem;white-space:pre-wrap;word-break:break-all}}
ul.ranked{{columns:3;font-size:.9rem}}</style>
</head><body>
<h1>Honeypot evidence report</h1>
<p><strong>Source IP:</strong> {_esc(ip)}<br>
<strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}<br>
<strong>Cumulative score:</strong> {_esc(identity.get('score', 0))}<br>
<strong>Status:</strong> {'BANNED' if identity.get('banned') else 'ACTIVE'}<br>
<strong>First seen:</strong> {_esc(identity.get('first_seen', 'n/a'))}<br>
<strong>Last seen:</strong> {_esc(identity.get('last_seen', 'n/a'))}<br>
<strong>Services touched:</strong> {_esc(', '.join(identity.get('services_touched') or []))}<br>
<strong>Tool detected:</strong> {_esc(identity.get('tool_detected') or 'none')}</p>
<h2>Score breakdown</h2><table><tr><th>Event</th><th>Count</th><th>Points</th></tr>{rows}</table>
<h2>Credentials attempted</h2><table><tr><th>Service</th><th>Username</th><th>Password</th><th>When</th></tr>{creds}</table>
<h2>Commands run</h2>
{ranked_block}
{transcript_block}
<p style="font-size:.85rem;color:#666">{len(commands)} command(s) recorded; the
full list is in commands.txt and commands.csv.</p>
<h2>Event count</h2><p>{len(events)} logged events included in events.jsonl.
Ban-log lines for this address are in fail2ban.log.</p>
<p style="margin-top:2rem;font-size:.85rem;color:#666">
Generated by Drosera. All interaction was with an emulated service; no real
system was accessed and no credential shown here was ever validated.</p>
</body></html>"""


def _esc(value) -> str:
    text = "" if value is None else str(value)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


@app.route("/admin/audit")
@require_auth
def admin_audit():
    records = []
    if AUDIT_LOG.is_file():
        for line in tail_lines(AUDIT_LOG, max_bytes=2 * 1024 * 1024)[-500:]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    records.reverse()
    return render_template("audit.html", records=records, csrf_token=g.csrf_token)


@app.route("/admin/settings")
@require_auth
def admin_settings():
    config = load_config()
    channels = {
        "webhook": bool(os.getenv("ALERT_WEBHOOK_URL", "").strip()),
        "telegram": bool(os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "").strip()
                         and os.getenv("ALERT_TELEGRAM_CHAT_ID", "").strip()),
        "syslog": bool(os.getenv("ALERT_SYSLOG_HOST", "").strip()),
        "jsonl": True,
        "fail2ban": (STORAGE_DIR / "evidence" / "fail2ban.log").exists(),
        "session_cam": os.getenv("CAM_ENABLED", "true").lower()
                       not in ("0", "false", "no"),
    }
    try:
        clips_stored = sum(1 for path in CLIP_DIR.iterdir() if path.is_file())
    except OSError:
        clips_stored = 0
    settings = {
        "ban_threshold": os.getenv("HONEYPOT_BAN_THRESHOLD", "35"),
        "tarpit_threshold": os.getenv("HONEYPOT_TARPIT_THRESHOLD", "5"),
        "rate_limit_rpm": os.getenv("RATE_LIMIT_RPM", "60"),
        "ban_ttl_days": round(BAN_TTL / 86400, 1),
        "session_ttl_hours": round(SESSION_TTL / 3600, 1),
        "fail2ban_log": str(STORAGE_DIR / "evidence" / "fail2ban.log"),
        "storage_dir": str(STORAGE_DIR),
        "max_storage_mb": os.getenv("HONEYPOT_MAX_STORAGE_MB", "4096"),
        "allowed_ips": ", ".join(config.get("allowed_ips") or ["127.0.0.1"]),
        "cam_min_score": os.getenv("CAM_MIN_SCORE", "5"),
        "cam_format": os.getenv("CAM_FORMAT", "gif"),
        "cam_retention_days": os.getenv("CAM_RETENTION_DAYS", "14"),
        "clips_stored": clips_stored,
    }
    return render_template("settings.html", channels=channels, settings=settings,
                           csrf_token=g.csrf_token)


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.errorhandler(403)
def forbidden(_error):
    return render_template("message.html", title="Forbidden",
                           message="Access denied."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("message.html", title="Not found",
                           message="No such page."), 404


if __name__ == "__main__":
    # Development only. Production runs under gunicorn (see Dockerfile).
    # Binds 0.0.0.0 inside the container; docker-compose publishes it to
    # 127.0.0.1 on the host only, so it is never exposed to the internet.
    app.run(host="0.0.0.0", port=8443, debug=False)
