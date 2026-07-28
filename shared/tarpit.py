"""Slow-drain helpers for the asyncio protocol services.

Strictly defensive: these hold an attacker's *own* connection open so their
scanner blocks, their socket table fills, and their run takes hours instead of
seconds. Nothing is ever sent toward attacker infrastructure and no traffic is
generated toward a third party -- the only resource being consumed on the far
side is the one they voluntarily pointed at us.

Every hold is deadline-bounded. An unbounded tarpit costs us a file descriptor
and a task for as long as it costs them one, so the ceiling matters as much for
our own stability as theirs.

ssh-honey keeps its own endlessh-style implementation: it tarpits before the
protocol starts, where there is no writer to drip through.
"""

import asyncio
import json
import os
import random
import time
from typing import Any, Optional

from . import alerting

MAX_HOLD_SECONDS = int(os.getenv("TARPIT_HOLD_MAX_SECONDS", "600"))
BYTE_DELAY = float(os.getenv("TARPIT_BYTE_DELAY", "1.5"))
# Ceiling on the gap between two bytes. Pacing a short PDU across a ten-minute
# window would otherwise mean half-minute silences, and clients start giving up.
MAX_BYTE_GAP = float(os.getenv("TARPIT_MAX_BYTE_GAP", "10"))
STALL_RANGE = (
    float(os.getenv("TARPIT_STALL_MIN", "4")),
    float(os.getenv("TARPIT_STALL_MAX", "15")),
)


def deadline(max_seconds: int = MAX_HOLD_SECONDS) -> float:
    return time.time() + max_seconds


async def stall(until: float, low: float = STALL_RANGE[0],
                high: float = STALL_RANGE[1]) -> float:
    """Sleep a random interval, never past `until`. Returns seconds slept.

    Randomised rather than fixed: a constant delay is a fingerprint, and a
    scanner that recognises the honeypot stops wasting time on it.
    """
    remaining = until - time.time()
    if remaining <= 0:
        return 0.0
    interval = min(random.uniform(low, high), remaining)
    await asyncio.sleep(interval)
    return interval


async def drip(writer: Any, data: bytes, until: float,
               byte_delay: float = 0.0) -> float:
    """Write `data` a byte at a time. Returns seconds held.

    A client blocks until it has a complete PDU, so trickling out a *valid*
    response holds it without ever sending anything malformed -- which is what
    keeps this working against clients that would drop a garbage response.

    With no explicit delay the write is paced to fill the whole hold window.
    Protocol handshakes are short -- an X.224 Connection Confirm is 19 bytes --
    so a fixed per-byte delay would finish in half a minute and hand the
    connection back rather than holding it for as long as we asked.
    """
    started = time.time()
    if byte_delay <= 0:
        remaining = max(until - started, 0.0)
        byte_delay = min(max(BYTE_DELAY, remaining / max(len(data), 1)),
                         MAX_BYTE_GAP)
    try:
        for index in range(len(data)):
            if time.time() > until:
                # Flush the remainder so we never leave a half PDU on the wire.
                writer.write(data[index:])
                await writer.drain()
                break
            writer.write(data[index:index + 1])
            await writer.drain()
            await asyncio.sleep(byte_delay)
    except (OSError, ConnectionResetError):
        pass
    return time.time() - started


def begin_hold(ip: str, service: str, max_seconds: float) -> Optional[str]:
    """Register a hold that is happening *now*, and return its key.

    `tarpit_active` on an identity only means the IP is marked for tarpitting;
    it says nothing about whether a socket is being drained at this moment.
    This is the live view -- what the operator wants when the question is "am I
    actually costing them anything right now".

    The key carries a TTL slightly longer than the maximum hold, so a container
    that dies mid-drain cannot leave a phantom connection on the dashboard
    forever.
    """
    from . import identity

    client = identity._client()
    if client is None:
        return None
    key = (f"hp:holding:{identity.hash_ip(ip)}:{service}:"
           f"{os.getpid()}:{time.time():.3f}")
    try:
        client.setex(key, int(max_seconds) + 30, json.dumps({
            "ip": ip,
            "service": service,
            "started": time.time(),
        }))
    except Exception:                                       # noqa: BLE001
        return None
    return key


def end_hold(key: Optional[str]) -> None:
    from . import identity

    if not key:
        return
    client = identity._client()
    if client is None:
        return
    try:
        client.delete(key)
    except Exception:                                       # noqa: BLE001
        pass


def log_hold(ip: str, service: str, seconds: float, reason: str = "") -> None:
    """Record how long a connection was pinned. Matches ssh-honey's TARPIT_HELD."""
    if seconds <= 0:
        return
    alerting.alert_event(
        ip=ip,
        event_type="TARPIT_HELD",
        service=service,
        reason=reason or f"{service} tarpit held connection {seconds:.0f}s",
        tarpit_active=True,
        held_seconds=round(seconds, 1),
    )
