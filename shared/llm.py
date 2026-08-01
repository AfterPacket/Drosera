"""LLM-written answers for commands the fake shell does not implement.

Off unless HONEYPOT_LLM=1, and every failure path returns None so the caller
falls back to `bash: <cmd>: command not found`. That fallback is not a
consolation prize -- it is better than the alternatives. A shell that pauses for
six seconds and then apologises for being an AI identifies itself in one line,
and a shell that stalls forever ends the session that was producing the intel.
Not knowing `tcpdump` is the most ordinary thing a stripped container can do.

NOTHING HERE OPENS A SOCKET, and it must stay that way. Egress from
honeypot-internal is dropped at the host firewall -- deploy/smoke-test.sh
asserts that ssh-honey cannot reach 1.1.1.1 -- so these containers could not
call an API even with one configured. Requests cross to llm-broker as files on
the storage volume, and llm-broker sits on an egress network and on no honeypot
network. That is the arrangement session-cam already uses, for the same reason:
the one container that can reach the internet must not be reachable from the
container an attacker is talking to.

Blocking on purpose. FakeShell blocks for its latency tiers already, and the
asyncio services call it through run_in_executor for exactly that reason
(telnet-honey/fake_telnetd.py:271), so a poll loop here needs no async variant.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ENABLED = os.getenv("HONEYPOT_LLM", "0").strip().lower() in ("1", "true", "yes", "on")

SPOOL = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage")) / "llm"
REQUESTS = SPOOL / "requests"
REPLIES = SPOOL / "replies"
STATUS = SPOOL / "status.json"

# The broker rewrites its status every five seconds, so a file older than this
# means the container is not there. Checking costs one stat and saves the whole
# timeout: without it, HONEYPOT_LLM=1 with the llm profile down makes every
# unknown command pause for six seconds and then answer `command not found`,
# which is a far louder tell than the instant answer it replaced.
STALE_AFTER = 60.0
_ALIVE_CACHE_SECONDS = 5.0

# Long by shell standards, short by model standards. A 3B model on CPU answers
# in one to three seconds; anything slower than this is not worth the wait
# because the attacker is sitting at a prompt watching nothing happen.
TIMEOUT = float(os.getenv("HONEYPOT_LLM_TIMEOUT", "6"))

# Engagement mode inverts the usual priority. Once a session is past the tarpit
# threshold the goal is no longer to look brisk, it is to hold them, so a slow
# answer is worth more than a fast fallback.
ENGAGED_TIMEOUT = float(os.getenv("HONEYPOT_LLM_ENGAGED_TIMEOUT", "20"))

POLL = 0.02

# A scan flood must not turn the spool into a disk-filling queue. Past this many
# unanswered requests the shell stops asking and answers the way it always did:
# the broker is down or slower than the traffic, and queueing more work makes
# both of those worse rather than better.
MAX_PENDING = int(os.getenv("HONEYPOT_LLM_MAX_PENDING", "32"))

# The broker enforces this too. Repeated here because a client that trusts a
# peer to bound a value is a client that hands over its whole output stream the
# day the peer has a bug.
MAX_REPLY_CHARS = int(os.getenv("HONEYPOT_LLM_MAX_CHARS", "2000"))

# Enough for the model to see what they are doing without carrying the whole
# session into every prompt.
HISTORY_LINES = 8


def enabled() -> bool:
    return ENABLED


# -inf rather than 0.0: time.monotonic()'s zero point is arbitrary, and on a
# platform where it starts near zero the first check would be skipped as though
# it had just run.
_alive_checked_at = float("-inf")
_alive = False


def _broker_alive() -> bool:
    """Whether a broker is up AND willing to answer. Cached; runs per command.

    Both halves matter. A broker that failed preflight -- a cloud provider
    without HONEYPOT_LLM_ALLOW_EGRESS, say -- keeps publishing its status so the
    dashboard can explain itself, so freshness alone would say yes and every
    command would wait out the full timeout for a reply that is never coming.
    """
    global _alive_checked_at, _alive

    now = time.monotonic()
    if now - _alive_checked_at < _ALIVE_CACHE_SECONDS:
        return _alive

    _alive_checked_at = now
    _alive = False
    try:
        if (time.time() - STATUS.stat().st_mtime) < STALE_AFTER:
            status = json.loads(STATUS.read_text(encoding="utf-8"))
            _alive = bool(isinstance(status, dict) and status.get("ready"))
    except (OSError, ValueError):
        _alive = False
    return _alive


def _pending() -> int:
    """How many requests are waiting. An unreadable spool counts as full."""
    try:
        return sum(1 for _ in REQUESTS.glob("*.json"))
    except OSError:
        return MAX_PENDING


def _write_request(request_id: str, payload: Dict[str, Any]) -> bool:
    """Write the request so the broker can never observe a partial one."""
    target = REQUESTS / f"{request_id}.json"
    staging = REQUESTS / f"{request_id}.tmp"
    try:
        REQUESTS.mkdir(parents=True, exist_ok=True)
        REPLIES.mkdir(parents=True, exist_ok=True)
        staging.write_text(json.dumps(payload), encoding="utf-8")
        # The broker globs *.json, so the file becomes visible under that name
        # only once it is complete. Writing in place would let it read half a
        # request and answer a truncated command.
        os.replace(staging, target)
        return True
    except OSError:
        try:
            staging.unlink()
        except OSError:
            pass
        return False


def _collect(request_id: str, deadline: float) -> Optional[str]:
    """Poll for the reply until the deadline. Returns None on anything wrong."""
    reply_path = REPLIES / f"{request_id}.json"
    while time.monotonic() < deadline:
        try:
            raw = reply_path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            time.sleep(POLL)
            continue

        try:
            reply_path.unlink()
        except OSError:
            pass

        try:
            reply = json.loads(raw)
        except ValueError:
            return None

        # The broker reports refusals as an error rather than as text, so a
        # response it rejected never reaches the attacker as output.
        if not isinstance(reply, dict) or reply.get("error"):
            return None
        text = reply.get("text")
        if not isinstance(text, str) or not text.strip():
            return None
        return text[:MAX_REPLY_CHARS]

    return None


def ask(command: str, *, ip: str, cwd: str, hostname: str, username: str,
        os_name: str, service: str, history: Optional[List[str]] = None,
        engaged: bool = False) -> Optional[str]:
    """Ask the broker what this command should print. None means fall back."""
    if not ENABLED or not command.strip():
        return None

    if not _broker_alive() or _pending() >= MAX_PENDING:
        return None

    request_id = uuid.uuid4().hex
    payload = {
        "id": request_id,
        "ts": time.time(),
        "command": command[:1000],
        "cwd": cwd,
        "hostname": hostname,
        "username": username,
        "os_name": os_name,
        "service": service,
        # Budgeting only. The broker caps calls per address so one noisy
        # scanner cannot spend the whole hour's allowance, and it never puts
        # this in a prompt -- the model has no reason to know who is asking.
        "ip": ip,
        "history": list(history or [])[-HISTORY_LINES:],
        "engaged": bool(engaged),
    }

    if not _write_request(request_id, payload):
        return None

    deadline = time.monotonic() + (ENGAGED_TIMEOUT if engaged else TIMEOUT)
    text = _collect(request_id, deadline)

    if text is None:
        # Timed out. Drop the request so a broker that is merely slow does not
        # come back to a queue of work whose sessions all ended minutes ago.
        try:
            (REQUESTS / f"{request_id}.json").unlink()
        except OSError:
            pass

    return text
