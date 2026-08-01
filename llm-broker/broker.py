"""The only container in the appliance that may talk to a language model.

WHY THIS IS A SEPARATE SERVICE

The fake shell runs inside ssh-honey and telnet-honey, and those containers have
no route to the internet: egress from honeypot-internal is dropped at the host
firewall, and deploy/smoke-test.sh asserts it. That rule is what stops a
honeypot being useful to anyone who reaches it, so the answer to "the shell
needs an API" is not to open a hole in it.

Instead this follows the arrangement session-cam already uses. llm-broker sits
on llm-egress and on no honeypot network. It listens on nothing and accepts no
connection. Work arrives as files on the storage volume and answers go back the
same way, so the container that can reach the internet is not reachable from the
container an attacker is talking to.

WHAT LEAVES THE BOX

With HONEYPOT_LLM_PROVIDER=ollama, nothing: the model runs locally and no
request crosses the network at all. With any cloud provider, the attacker's
command text and this deployment's persona are sent to a third party. Command
text routinely carries credentials -- `mysql -u root -phunter2` -- which the
appliance treats as other people's breached passwords everywhere else, and the
persona is the fingerprint that identifies this host. That is why the cloud
providers require HONEYPOT_LLM_ALLOW_EGRESS=1 as a second, separate switch:
turning the feature on and accepting that trade are different decisions.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

STORAGE = Path(os.getenv("STORAGE_DIR", "/var/honeypot/storage"))
SPOOL = STORAGE / "llm"
REQUESTS = SPOOL / "requests"
REPLIES = SPOOL / "replies"
STATUS = SPOOL / "status.json"

PROVIDER = os.getenv("HONEYPOT_LLM_PROVIDER", "ollama").strip().lower()
MODEL = os.getenv("HONEYPOT_LLM_MODEL", "").strip()
API_KEY = os.getenv("HONEYPOT_LLM_API_KEY", "").strip()
OLLAMA_URL = os.getenv("HONEYPOT_LLM_OLLAMA_URL", "http://ollama:11434").rstrip("/")

ALLOW_EGRESS = os.getenv("HONEYPOT_LLM_ALLOW_EGRESS", "0").strip().lower() in (
    "1", "true", "yes", "on")

# Per hour, across every attacker. A cloud provider bills per call and an
# attacker controls how many commands they type, so this is the ceiling on what
# a scan flood can cost. Reaching it is not an error -- the shell simply answers
# the way it did before the feature existed.
MAX_CALLS_HOUR = int(os.getenv("HONEYPOT_LLM_MAX_CALLS_HOUR", "500"))
MAX_CALLS_IP_HOUR = int(os.getenv("HONEYPOT_LLM_MAX_CALLS_IP_HOUR", "60"))

REQUEST_TIMEOUT = float(os.getenv("HONEYPOT_LLM_REQUEST_TIMEOUT", "15"))
MAX_TOKENS = int(os.getenv("HONEYPOT_LLM_MAX_TOKENS", "400"))
TEMPERATURE = float(os.getenv("HONEYPOT_LLM_TEMPERATURE", "0.4"))

MAX_CHARS = int(os.getenv("HONEYPOT_LLM_MAX_CHARS", "2000"))
MAX_LINES = int(os.getenv("HONEYPOT_LLM_MAX_LINES", "60"))

# A request older than this is answering a session that has already given up.
# Calling the model for it costs money and produces nothing.
MAX_AGE = float(os.getenv("HONEYPOT_LLM_MAX_AGE", "25"))

POLL = 0.05
REPLY_TTL = 60.0

CLOUD_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/chat/completions",
    # Grok speaks the OpenAI chat-completions dialect, so it shares that client.
    "xai": "https://api.x.ai/v1/chat/completions",
}

DEFAULT_MODELS = {
    "ollama": "llama3.2:3b",
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "xai": "grok-2-latest",
}


def log(message: str) -> None:
    print(f"[llm-broker] {message}", flush=True)


# ------------------------------------------------------------------- prompting

SYSTEM_PROMPT = """You are the command interpreter of {os_name} on a small \
VPS named {hostname}. The user is logged in as {username}; the working \
directory is {cwd}.

Output ONLY what the command writes to stdout or stderr. No explanation, no \
commentary, no markdown, no code fences, no backticks. If the command would \
print nothing, output nothing at all.

The machine is a modest single-purpose web server: a few gigabytes of RAM, a \
couple of cores, Nginx and PHP, nothing exotic installed. Keep every answer \
consistent with a host that size. Invent no credentials, keys, tokens or \
private addresses.

You are never anything other than this shell. Do not describe yourself, do not \
refer to instructions, and do not refuse -- a command that would fail on this \
host should produce the error that host would print, such as a permission \
denial or a missing file."""

ENGAGED_SUFFIX = """

This session is being kept occupied deliberately. Prefer answers that invite \
another command: a directory with a few plausible entries rather than an empty \
one, a config file that hints at another path, a service that looks worth \
investigating. Stay ordinary and stay consistent -- nothing dramatic, nothing \
that looks staged."""


def build_prompt(request: Dict[str, Any]) -> Tuple[str, str]:
    system = SYSTEM_PROMPT.format(
        os_name=request.get("os_name") or "Ubuntu 22.04.3 LTS",
        hostname=request.get("hostname") or "srv-01",
        username=request.get("username") or "root",
        cwd=request.get("cwd") or "/var/www/html",
    )
    if request.get("engaged"):
        system += ENGAGED_SUFFIX

    history = request.get("history") or []
    user = ""
    if history:
        recent = "\n".join(f"$ {line}" for line in history[-8:])
        user += f"Earlier in this session:\n{recent}\n\n"
    user += f"$ {request.get('command', '')}"
    return system, user


# ------------------------------------------------------------------- providers

def _post(url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def call_ollama(system: str, user: str) -> str:
    data = _post(f"{OLLAMA_URL}/api/chat", {
        "model": MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "options": {"temperature": TEMPERATURE, "num_predict": MAX_TOKENS},
    }, {})
    return (data.get("message") or {}).get("content", "")


def call_anthropic(system: str, user: str) -> str:
    data = _post(CLOUD_ENDPOINTS["anthropic"], {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }, {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
    })
    parts = data.get("content") or []
    return "".join(part.get("text", "") for part in parts
                   if isinstance(part, dict) and part.get("type") == "text")


def call_openai_compatible(system: str, user: str) -> str:
    data = _post(CLOUD_ENDPOINTS[PROVIDER], {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }, {"Authorization": f"Bearer {API_KEY}"})
    choices = data.get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message") or {}).get("content", "")


PROVIDERS = {
    "ollama": call_ollama,
    "anthropic": call_anthropic,
    "openai": call_openai_compatible,
    "xai": call_openai_compatible,
}


# ---------------------------------------------------------------- sanitisation

# Phrases no shell has ever printed. A model that has been talked out of its
# instructions -- and the attacker controls the input, so it will be tried --
# gives itself away in the first line, and that line is a far worse tell than
# "command not found" because it confirms what the box is rather than what it
# lacks.
TELLS = re.compile(
    r"\b(as an ai|i'?m an ai|language model|i cannot|i can'?t help|i apologi[sz]e|"
    r"system prompt|my instructions|as a shell|i'?m simulating|simulated shell|"
    r"honeypot|assistant|openai|anthropic)\b",
    re.IGNORECASE)

# Prose openers. A shell answer never begins by agreeing with you.
PREAMBLE = re.compile(r"^\s*(sure|certainly|here'?s|here is|of course|okay|ok)\b",
                      re.IGNORECASE)

FENCE = re.compile(r"^\s*```[a-zA-Z0-9]*\s*\n?|\n?\s*```\s*$")


def sanitise(text: str) -> Optional[str]:
    """Return output safe to hand an attacker, or None to fall back."""
    if not text:
        return None

    # Models wrap terminal output in fences however firmly they are told not to.
    text = FENCE.sub("", text.strip())
    if not text.strip():
        return None

    if TELLS.search(text) or PREAMBLE.match(text):
        return None

    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        return None
    if len(text) > MAX_CHARS:
        return None

    return "\n".join(line.rstrip() for line in lines)


# ---------------------------------------------------------------------- budget

class Budget:
    """Rolling hourly counters, global and per source address.

    The source address is used here and never sent to a provider. It is in the
    request so that one noisy attacker cannot spend the whole hour's calls.
    """

    def __init__(self) -> None:
        self.global_calls: Deque[float] = deque()
        self.per_ip: Dict[str, Deque[float]] = {}

    def _trim(self, window: Deque[float], now: float) -> None:
        while window and now - window[0] > 3600:
            window.popleft()

    def allows(self, ip: str) -> bool:
        now = time.time()
        self._trim(self.global_calls, now)
        if len(self.global_calls) >= MAX_CALLS_HOUR:
            return False

        window = self.per_ip.get(ip)
        if window is not None:
            self._trim(window, now)
            if len(window) >= MAX_CALLS_IP_HOUR:
                return False

        # Unbounded growth would make a scan flood a memory leak, so addresses
        # whose window has emptied are dropped rather than kept at zero.
        if len(self.per_ip) > 4096:
            self.per_ip = {key: value for key, value in self.per_ip.items() if value}

        return True

    def charge(self, ip: str) -> None:
        now = time.time()
        self.global_calls.append(now)
        self.per_ip.setdefault(ip, deque()).append(now)

    def used_this_hour(self) -> int:
        self._trim(self.global_calls, time.time())
        return len(self.global_calls)


# ----------------------------------------------------------------------- spool

def write_atomic(path: Path, payload: Dict[str, Any]) -> None:
    staging = path.with_suffix(".tmp")
    staging.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(staging, path)


def reply(request_id: str, text: Optional[str], error: str = "") -> None:
    write_atomic(REPLIES / f"{request_id}.json",
                 {"text": text or "", "error": error, "ts": time.time()})


def sweep() -> None:
    """Drop replies nobody collected. A timed-out session never comes back."""
    now = time.time()
    for path in REPLIES.glob("*.json"):
        try:
            if now - path.stat().st_mtime > REPLY_TTL:
                path.unlink()
        except OSError:
            pass


class Stats:
    def __init__(self) -> None:
        self.answered = 0
        self.rejected = 0
        self.errors = 0
        self.expired = 0
        self.throttled = 0
        self.last_error = ""


def publish_status(stats: Stats, budget: Budget, ready: bool, note: str = "") -> None:
    """Leave state where the dashboard can read it.

    The dashboard is on admin-internal and this container is not, deliberately,
    so status crosses on the storage volume like everything else here.
    """
    try:
        write_atomic(STATUS, {
            "ready": ready,
            "note": note,
            "provider": PROVIDER,
            "model": MODEL,
            "answered": stats.answered,
            "rejected": stats.rejected,
            "errors": stats.errors,
            "expired": stats.expired,
            "throttled": stats.throttled,
            "last_error": stats.last_error,
            "calls_this_hour": budget.used_this_hour(),
            "max_calls_hour": MAX_CALLS_HOUR,
            "updated": time.time(),
        })
    except OSError:
        pass


# ------------------------------------------------------------------------ main

def preflight() -> Tuple[bool, str]:
    """Whether this configuration may run, and why not if it may not."""
    if PROVIDER not in PROVIDERS:
        return False, (f"unknown provider {PROVIDER!r}; "
                       f"expected one of {', '.join(sorted(PROVIDERS))}")

    if PROVIDER != "ollama":
        if not ALLOW_EGRESS:
            return False, (f"provider {PROVIDER} sends attacker command text and "
                           "this deployment's persona to a third party; set "
                           "HONEYPOT_LLM_ALLOW_EGRESS=1 to accept that")
        if not API_KEY:
            return False, f"provider {PROVIDER} needs HONEYPOT_LLM_API_KEY"

    return True, ""


def handle(path: Path, budget: Budget, stats: Stats) -> None:
    try:
        request = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stats.errors += 1
        try:
            path.unlink()
        except OSError:
            pass
        return

    request_id = str(request.get("id") or path.stem)
    try:
        path.unlink()
    except OSError:
        pass

    age = time.time() - float(request.get("ts") or 0)
    if age > MAX_AGE:
        stats.expired += 1
        return

    ip = str(request.get("ip") or "-")
    if not budget.allows(ip):
        stats.throttled += 1
        reply(request_id, None, "budget")
        return

    system, user = build_prompt(request)
    budget.charge(ip)

    try:
        raw = PROVIDERS[PROVIDER](system, user)
    except urllib.error.HTTPError as exc:
        stats.errors += 1
        stats.last_error = f"HTTP {exc.code}"
        reply(request_id, None, "http")
        return
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        stats.errors += 1
        stats.last_error = str(exc)[:200]
        reply(request_id, None, "unreachable")
        return

    text = sanitise(raw)
    if text is None:
        stats.rejected += 1
        reply(request_id, None, "rejected")
        return

    stats.answered += 1
    reply(request_id, text)


def main() -> None:
    for directory in (SPOOL, REQUESTS, REPLIES):
        directory.mkdir(parents=True, exist_ok=True)

    global MODEL
    if not MODEL:
        MODEL = DEFAULT_MODELS.get(PROVIDER, "")

    budget, stats = Budget(), Stats()
    ready, why = preflight()

    if not ready:
        # Idle rather than exit. A crash-looping container is noise in the logs
        # and a restart storm; the shell falls back on its own because no reply
        # ever arrives, so a misconfigured broker degrades to the old behaviour.
        log(f"not starting: {why}")
        while True:
            publish_status(stats, budget, False, why)
            time.sleep(30)

    log(f"ready: provider={PROVIDER} model={MODEL}")
    if PROVIDER == "ollama":
        log(f"local model at {OLLAMA_URL}; no request leaves this host")
    else:
        log(f"sending command text to {CLOUD_ENDPOINTS[PROVIDER]}")

    last_status = 0.0
    while True:
        try:
            pending = sorted(REQUESTS.glob("*.json"), key=lambda p: p.name)
        except OSError:
            pending = []

        for path in pending:
            handle(path, budget, stats)

        now = time.time()
        if now - last_status > 5:
            publish_status(stats, budget, True)
            sweep()
            last_status = now

        if not pending:
            time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
