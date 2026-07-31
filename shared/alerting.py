"""Multi-channel alerting and session recording.

Every channel is best-effort: dispatch happens on a bounded background queue so a
slow webhook or a full disk can never block or crash a protocol handler. If the
queue fills, events are dropped rather than allowed to consume memory.

Channels are enabled by setting their environment variables. JSONL and session
recording are always on. Outbound channels (webhook, telegram, syslog) require
the honeypot network to permit egress, which it does not by default -- see
deploy/README.md.
"""

import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
LOG_DIR = STORAGE_DIR / "logs"
SESSION_DIR = STORAGE_DIR / "sessions"
EVIDENCE_DIR = STORAGE_DIR / "evidence"

WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
TELEGRAM_TOKEN = os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("ALERT_TELEGRAM_CHAT_ID", "").strip()
SYSLOG_HOST = os.getenv("ALERT_SYSLOG_HOST", "").strip()
SYSLOG_PORT = int(os.getenv("ALERT_SYSLOG_PORT", "514"))
OUTBOUND_TIMEOUT = float(os.getenv("ALERT_TIMEOUT_SECONDS", "4"))

# Fail-safe: stop writing once the storage tree exceeds this, so a sustained
# attack cannot fill the VPS disk and take the box down.
MAX_STORAGE_MB = int(os.getenv("HONEYPOT_MAX_STORAGE_MB", "4096"))
MAX_SESSION_BYTES = int(os.getenv("HONEYPOT_MAX_SESSION_BYTES", "2097152"))
_DISK_CHECK_INTERVAL = 60

_queue: "queue.Queue[tuple]" = queue.Queue(maxsize=2000)
_worker_started = False
_worker_lock = threading.Lock()
_dropped = 0

_disk_state = {"checked_at": 0.0, "full": False}
_disk_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dirs() -> None:
    for directory in (LOG_DIR, SESSION_DIR, EVIDENCE_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def _storage_full() -> bool:
    """Cheap cached check so we do not stat the tree on every event."""
    now = time.time()
    with _disk_lock:
        if now - _disk_state["checked_at"] < _DISK_CHECK_INTERVAL:
            return _disk_state["full"]
        _disk_state["checked_at"] = now
    total = 0
    try:
        for path in STORAGE_DIR.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
                if total > MAX_STORAGE_MB * 1024 * 1024:
                    break
    except Exception:
        total = 0
    full = total > MAX_STORAGE_MB * 1024 * 1024
    with _disk_lock:
        _disk_state["full"] = full
    return full


def _start_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    with _worker_lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_worker_loop, name="alerting", daemon=True)
        thread.start()
        _worker_started = True


def _worker_loop() -> None:
    while True:
        try:
            kind, payload = _queue.get()
        except Exception:
            continue
        try:
            if kind == "jsonl":
                _write_jsonl(payload)
            elif kind == "fail2ban":
                _write_fail2ban(payload)
            elif kind == "webhook":
                _post_webhook(payload)
            elif kind == "telegram":
                _post_telegram(payload)
            elif kind == "syslog":
                _send_syslog(payload)
        except Exception:
            pass
        finally:
            try:
                _queue.task_done()
            except Exception:
                pass


def _enqueue(kind: str, payload: Any) -> None:
    global _dropped
    _start_worker()
    try:
        _queue.put_nowait((kind, payload))
    except queue.Full:
        _dropped += 1


def _write_jsonl(event: Dict[str, Any]) -> None:
    if _storage_full():
        return
    _ensure_dirs()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(LOG_DIR / f"{day}.jsonl", "a", encoding="utf-8") as handle:
        # Compact separators to match PHP's json_encode, which writes
        # `"service":"web"` while Python's default writes `"service": "web"`.
        # The two producers share this file, and the inconsistency silently
        # breaks grep-based analysis: a pattern written against one producer's
        # spacing skips every line from the other, under-counting without any
        # sign that it has. Anything parsing the JSON properly was unaffected.
        handle.write(json.dumps(event, default=str, separators=(",", ":")) + "\n")


def _write_fail2ban(record: Dict[str, Any]) -> None:
    _ensure_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"[{stamp}] HONEYPOT_BAN ip={record['ip']} score={record['score']} "
        f"reason={record['reason']} tool={record['tool']} services={record['services']}\n"
    )
    with open(EVIDENCE_DIR / "fail2ban.log", "a", encoding="utf-8") as handle:
        handle.write(line)


def _post_webhook(event: Dict[str, Any]) -> None:
    if not WEBHOOK_URL:
        return
    body = json.dumps(event, default=str).encode()
    request = urllib.request.Request(
        WEBHOOK_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "drosera/1.0"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=OUTBOUND_TIMEOUT).close()
    except (urllib.error.URLError, OSError):
        pass


def _post_telegram(text: str) -> None:
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        return
    body = urllib.parse.urlencode({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text[:4000],
        "disable_web_page_preview": "true",
    }).encode()
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    request = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=OUTBOUND_TIMEOUT).close()
    except (urllib.error.URLError, OSError):
        pass


def _send_syslog(event: Dict[str, Any]) -> None:
    """RFC 5424 over UDP. Facility 13 (log audit), severity 4 (warning) -> PRI 108."""
    if not SYSLOG_HOST:
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    hostname = socket.gethostname()[:255] or "-"
    structured = (
        f'[honeypot@47111 ip="{_sd(event.get("real_ip"))}" '
        f'service="{_sd(event.get("service"))}" '
        f'event="{_sd(event.get("event_type"))}" '
        f'score="{_sd(event.get("cumulative_score"))}" '
        f'tool="{_sd(event.get("tool_detected"))}"]'
    )
    message = (
        f"<108>1 {timestamp} {hostname} drosera - {_sd(event.get('event_type')) or '-'} "
        f"{structured} {json.dumps(event, default=str)}"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(OUTBOUND_TIMEOUT)
        sock.sendto(message.encode("utf-8", "replace")[:8192], (SYSLOG_HOST, SYSLOG_PORT))
    except OSError:
        pass
    finally:
        sock.close()


def _sd(value: Any) -> str:
    """Escape a value for an RFC 5424 structured-data field."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")[:200]


def alert_event(ip: str, event_type: str, reason: str = "", service: str = "",
                score_delta: float = 0, cumulative_score: float = 0,
                tool: str = "", services: str = "", payload: str = "",
                tarpit_active: bool = False, fake_hostname: str = "",
                banned: bool = False, headers: Optional[Dict[str, Any]] = None,
                **extra: Any) -> None:
    """Record an event to JSONL and fan out to any configured outbound channels."""
    event: Dict[str, Any] = {
        "timestamp": _now(),
        "real_ip": ip,
        "service": service,
        "event_type": event_type,
        "reason": reason,
        "payload_excerpt": (payload or "")[:500],
        "score_delta": score_delta,
        "cumulative_score": cumulative_score,
        "tool_detected": tool or None,
        "tarpit_active": tarpit_active,
        "services_touched": services,
        "fake_hostname": fake_hostname,
        "banned": banned,
    }
    if headers:
        event["headers"] = headers
    if extra:
        event.update(extra)

    _enqueue("jsonl", event)
    if WEBHOOK_URL:
        _enqueue("webhook", event)
    if SYSLOG_HOST:
        _enqueue("syslog", event)
    if TELEGRAM_TOKEN and event_type in _TELEGRAM_EVENTS:
        _enqueue("telegram", _telegram_text(event))


_TELEGRAM_EVENTS = {
    "BAN", "TARPIT_ENGAGED", "REVERSE_SHELL", "SQLI_OOB",
    "FILE_UPLOAD", "TOOL_METASPLOIT", "TOOL_SQLMAP",
    # Not an attack -- the appliance telling you it has stopped enforcing.
    # Losing the identity store leaves every service answering and logging
    # while nothing is scored, tarpitted or banned, and that looks identical
    # to a quiet day unless something says so out loud.
    "IDENTITY_STORE_DEGRADED", "IDENTITY_STORE_RECOVERED",
}


def _telegram_text(event: Dict[str, Any]) -> str:
    return (
        f"[drosera] {event['event_type']}\n"
        f"IP: {event['real_ip']}\n"
        f"Service: {event.get('service') or 'n/a'}\n"
        f"Score: {event.get('cumulative_score')}\n"
        f"Tool: {event.get('tool_detected') or 'none'}\n"
        f"Reason: {event.get('reason')}"
    )


def log_ban_event(ip: str, score: float = 0, reason: str = "", tool: str = "",
                  services: str = "") -> None:
    """Write the fail2ban trigger line and raise a ban alert on every channel."""
    _enqueue("fail2ban", {
        "ip": ip, "score": score, "reason": reason or "THRESHOLD",
        "tool": tool or "none", "services": services or "none",
    })
    alert_event(ip=ip, event_type="BAN", reason=reason, cumulative_score=score,
                tool=tool, services=services, banned=True)


def log_session_start(ip: str, service: str, credentials: Optional[Dict[str, str]] = None) -> None:
    alert_event(ip=ip, event_type="SESSION_START", service=service,
                reason=f"Session opened on {service}",
                payload=json.dumps(credentials or {}))


def log_session_end(ip: str, service: str, duration: float) -> None:
    alert_event(ip=ip, event_type="SESSION_END", service=service,
                reason=f"Session closed after {duration:.1f}s", duration=duration)


class SessionRecorder:
    """asciinema v2 writer. Emits a header line then [offset, "o", data] frames.

    Silently stops recording past MAX_SESSION_BYTES so a tarpitted attacker
    cannot grow a single .cast file without bound.
    """

    def __init__(self, ip: str, service: str, width: int = 80, height: int = 24,
                 title: str = ""):
        self.ip = ip
        self.service = service
        self.started = time.time()
        self.bytes_written = 0
        self.frames = 0
        self.closed = False
        self.path: Optional[Path] = None
        self.width = width
        self.height = height
        self.title = title or f"{service} session from {ip}"
        self._lock = threading.Lock()
        self._handle = None

        if _storage_full():
            return
        try:
            _ensure_dirs()
            safe_ip = ip.replace(":", "_").replace("/", "_")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            self.path = SESSION_DIR / f"{safe_ip}_{stamp}_{service}.cast"
            self._handle = open(self.path, "w", encoding="utf-8")
            header = {
                "version": 2,
                "width": width,
                "height": height,
                "timestamp": int(self.started),
                "title": self.title,
                "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
            }
            self._handle.write(json.dumps(header) + "\n")
            self._handle.flush()
        except Exception:
            self._handle = None

    def _write(self, stream: str, data: str) -> None:
        if self._handle is None or self.closed:
            return
        with self._lock:
            if self.bytes_written > MAX_SESSION_BYTES:
                return
            try:
                frame = json.dumps([round(time.time() - self.started, 6), stream, data])
                self._handle.write(frame + "\n")
                self._handle.flush()
                self.bytes_written += len(frame)
                self.frames += 1
            except Exception:
                pass

    def write_output(self, data: str) -> None:
        self._write("o", data)

    def write_input(self, data: str) -> None:
        self._write("i", data)

    def _write_meta(self) -> None:
        """Sidecar describing a finished recording.

        Its appearance is what tells session-cam a .cast is complete and safe to
        render -- that service reads recordings off the shared volume and has no
        Redis of its own, so every bit of context it needs to caption a clip has
        to be carried here. Written tmp-then-rename so the watcher can never pick
        up a half-written file.
        """
        if self.path is None:
            return

        meta: Dict[str, Any] = {
            "version": 1,
            "cast": self.path.name,
            "ip": self.ip,
            "service": self.service,
            "title": self.title,
            "width": self.width,
            "height": self.height,
            "started_at": datetime.fromtimestamp(self.started, timezone.utc).isoformat(),
            "duration": round(time.time() - self.started, 1),
            "frames": self.frames,
            "bytes": self.bytes_written,
            "truncated": self.bytes_written > MAX_SESSION_BYTES,
        }

        # Deferred import: identity imports this module, so a module-level import
        # would close the cycle.
        try:
            from . import identity as _identity

            ident = _identity.get_or_create_identity(self.ip)
            meta.update({
                "score": float(ident.get("score") or 0),
                "tool": ident.get("tool_detected") or "",
                "services_touched": list(ident.get("services_touched") or []),
                "fake_hostname": ident.get("fake_hostname", ""),
                "banned": bool(ident.get("banned")),
                "tarpit_active": bool(ident.get("tarpit_active")),
                "credentials": [
                    f"{c.get('username', '')}:{c.get('password', '')}"
                    for c in (ident.get("credentials") or [])[-10:]
                ],
            })
        except Exception:
            pass

        tmp = self.path.with_suffix(".meta.tmp")
        try:
            tmp.write_text(json.dumps(meta, default=str), encoding="utf-8")
            tmp.replace(self.path.with_suffix(".meta.json"))
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:
                pass
        # After the handle is closed, so the sidecar never advertises a cast that
        # still has buffered frames outstanding.
        self._write_meta()
        log_session_end(self.ip, self.service, time.time() - self.started)

    def __enter__(self) -> "SessionRecorder":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
