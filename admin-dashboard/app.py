#!/usr/bin/env python3
"""Drosera operator dashboard.

Deliberately shares nothing with the honeypot: its own Redis instance, its own
auth, its own network. It opens redis-honeypot read-only, and the only writes it
ever makes there are explicit operator ban/unban actions.

Auth is two-stage and both stages are required. A session is only created after
TOTP succeeds -- there is no intermediate state that grants access.
"""

import fnmatch
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
                   request, send_file, url_for)

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

def iter_identities():
    """Yield (ip_hash, identity dict) for every tracked IP."""
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


def log_files():
    directory = STORAGE_DIR / "logs"
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.jsonl"), reverse=True)


def tail_lines(path: Path, max_bytes: int = 8 * 1024 * 1024) -> list:
    """Return the last max_bytes of a file as lines.

    Log files can reach 100MB between rotations; reading one whole would blow
    the container's memory limit. Seek instead and drop the first (likely
    partial) line.
    """
    try:
        size = path.stat().st_size
        with open(path, "rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                partial = True
            else:
                partial = False
            raw = handle.read()
    except OSError:
        return []
    lines = raw.decode("utf-8", "replace").splitlines()
    return lines[1:] if partial and lines else lines


def read_events(limit=200, ip_filter=None, since=None, max_files=7):
    """Read newest-first across daily JSONL files, stopping once limit is met."""
    events = []
    for path in log_files()[:max_files]:
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
    for _, identity in iter_identities():
        rows.append({
            # Written by both the PHP engine and the Python services.
            "ip": identity.get("ip") or "unknown",
            "first_seen": identity.get("first_seen", ""),
            "last_seen": identity.get("last_seen", ""),
            "score": identity.get("score", 0),
            "services": ", ".join(identity.get("services_touched") or []),
            "tool": identity.get("tool_detected") or "-",
            "status": status_of(identity),
        })
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return render_template("dashboard.html", rows=rows, csrf_token=g.csrf_token)


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

    return render_template(
        "ip_detail.html",
        ip=ip, identity=identity, status=status_of(identity), country=country,
        breakdown=sorted(breakdown.items(), key=lambda kv: -kv[1]["points"]),
        credentials=(identity.get("credentials") or [])[-100:],
        commands=[e for e in history if e.get("event_type") == "WEBSHELL_CMD"][-100:],
        payloads=[e for e in history
                  if e.get("event_type") in ("SQLI_BASIC", "SQLI_UNION_BLIND", "SQLI_OOB",
                                             "PHP_EVAL_ATTEMPT", "FILE_UPLOAD",
                                             "REVERSE_SHELL")][-100:],
        timeline=history[-200:],
        events=events[start:start + per_page],
        page=page, total_pages=max(1, (len(events) + per_page - 1) // per_page),
        sessions=session_files(ip), csrf_token=g.csrf_token,
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


def read_day(day: str, limit: int = 80000):
    """Every event from one UTC day.

    The event log is already one file per day, so daily history needs no extra
    storage and no rollup job -- logrotate's retention *is* the retention. This
    reads one file rather than tailing the most recent few, which is what makes
    an arbitrary past day as cheap to render as today.
    """
    path = STORAGE_DIR / "logs" / f"{day}.jsonl"
    events = []
    if not path.is_file():
        return events
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if len(events) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    events.append(parsed)
    except OSError:
        pass
    return events


def available_days():
    directory = STORAGE_DIR / "logs"
    if not directory.is_dir():
        return []
    days = [p.stem for p in directory.glob("*.jsonl") if len(p.stem) == 10]
    return sorted(days, reverse=True)


@app.route("/api/stats")
@require_auth
def api_stats():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day = request.args.get("day", today)
    # Path component, so validate rather than trust: this becomes a filename.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day or ""):
        day = today

    cache_key = f"admin:stats:v2:{day}"
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

        address = event.get("real_ip")
        if address:
            seen_ips.add(address)
            score = float(event.get("cumulative_score") or 0)
            if score > peak_score.get(address, 0):
                peak_score[address] = score
            if event.get("tool_detected"):
                tool_by_ip[address] = event["tool_detected"]
            if event.get("service"):
                services_by_ip.setdefault(address, set()).add(event["service"])

        kind = event.get("event_type")
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
    for address in seen_ips:
        record = geoip.lookup(address)
        code = (record or {}).get("country_code")
        countries[code or "unknown"] += 1
        if not record or record.get("lat") is None:
            continue
        # Bucketed to whole degrees: a city's worth of scanners becomes one
        # readable dot instead of a hundred overlapping ones.
        key = (round(float(record["lat"])), round(float(record["lon"])))
        bucket = origins.setdefault(key, {
            "lat": key[0], "lon": key[1], "count": 0,
            "label": record.get("city") or record.get("country") or code or "?",
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
        "countries": [{"country": k, "count": v}
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


@app.route("/api/export/<path:ip>", methods=["POST", "GET"])
@require_auth
def api_export(ip):
    if request.method == "POST":
        require_csrf()

    ip = safe_ip(ip)
    identity = resolve_identity(ip)
    events = read_events(limit=5000, ip_filter=ip)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{ip}/events.jsonl",
                         "\n".join(json.dumps(e, default=str) for e in events))
        if identity:
            archive.writestr(f"{ip}/identity.json",
                             json.dumps(identity, indent=2, default=str))
        for meta in session_files(ip):
            path = STORAGE_DIR / "sessions" / meta["name"]
            if path.is_file():
                archive.write(path, f"{ip}/sessions/{meta['name']}")
        archive.writestr(f"{ip}/suggested-fail2ban.txt",
                         f"# Add to your jail or run directly:\n"
                         f"fail2ban-client set honeypot banip {ip}\n"
                         f"ufw insert 1 deny from {ip} to any\n")
        archive.writestr(f"{ip}/report.html", _report_html(ip, identity, events))

    buffer.seek(0)
    audit("EVIDENCE_EXPORT", target_ip=ip, event_count=len(events))
    return send_file(buffer, mimetype="application/zip", as_attachment=True,
                     download_name=f"evidence-{ip.replace(':', '_')}.zip")


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
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Evidence report {_esc(ip)}</title>
<style>body{{font-family:sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;margin:1rem 0;width:100%}}
th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:.9rem}}
th{{background:#eee}}h1{{border-bottom:3px solid #333;padding-bottom:.4rem}}</style>
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
<h2>Event count</h2><p>{len(events)} logged events included in events.jsonl.</p>
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
