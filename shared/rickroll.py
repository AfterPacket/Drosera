"""What a banned address gets, on every tier, from one file.

`RICKROLL_URL` on its own reaches almost none of the traffic that earns a ban.
A 302 is only a rickroll to something that follows redirects, and the clients
that get themselves banned here are `SSH-2.0-Go` worms and curl-based scanners
that do not -- and over SSH and telnet there is no Location header to send in
the first place. So the payload is text, in `rickroll.txt` next to this file,
and all three tiers read that one file: `web/lib/drosera.php` serves it as
`text/plain` when the client did not ask for HTML, keeping the redirect for
real browsers, and the two terminal services write it down the socket.

It is dripped rather than sent, which makes it part of the tarpit instead of a
separate feature: the last thing a banned scanner does here is spend minutes
collecting a picture.

This is deliberately the one place the deception is dropped. Everywhere else the
project works to look like an ordinary neglected server; at the ban threshold
the address has already been scored past 35, written to the fail2ban evidence
log and firewalled at the host, so there is no illusion left to protect. The
art is a published constant and therefore a fingerprint for drosera -- but only
for someone who has already been caught, which is why the web tier was willing
to hardcode a YouTube URL in the first place.

Operators who would rather not editorialise can set `HONEYPOT_RICKROLL=0`, and
the services fall back to dropping the connection without a word.
"""

import os
import threading
import time
from pathlib import Path

ART_FILE = Path(__file__).with_name("rickroll.txt")

# A mangled or hand-edited mount should not put an unbounded read in front of
# every banned connection.
MAX_BYTES = 64 * 1024

# How long the drip is allowed to take. The art is about a kilobyte, so at the
# tarpit's normal per-byte pacing it would run for twenty minutes and hold a
# thread the whole time; this bounds it to something that still costs them real
# minutes without costing us a connection slot all afternoon.
DRIP_SECONDS = float(os.getenv("HONEYPOT_RICKROLL_DRIP_SECONDS", "120"))

# One recording per address per interval, not one per connection.
#
# A banned scanner reconnects every few seconds and is handed the identical
# picture every time. Recording each delivery produced 321 near-identical files
# for a single address in half an hour, filled every slot in the live feed so
# nothing else was visible, and left the profile page stitching a 321-segment
# playback of the same drawing. The first delivery is the evidence; the 321st is
# the same evidence again. The drip itself still runs every time -- their time is
# the point -- and log_hold still counts every second of it.
RECORD_INTERVAL = float(os.getenv("HONEYPOT_RICKROLL_RECORD_INTERVAL", "3600"))
_MAX_TRACKED = 4096

_lock = threading.Lock()
_tried = False
_rendered = b""
_recorded: dict = {}
_recorded_lock = threading.Lock()


def should_record(ip: str) -> bool:
    """True at most once per RECORD_INTERVAL for a given address.

    Process-local rather than Redis-backed on purpose: this is a bound on our
    own disk writes, and it has to hold when the identity store is down --
    which is precisely when a flood is least welcome. A restart forgets, which
    costs one extra recording per address.
    """
    if RECORD_INTERVAL <= 0:
        return True
    now = time.time()
    with _recorded_lock:
        if now - _recorded.get(ip, 0.0) < RECORD_INTERVAL:
            return False
        if len(_recorded) >= _MAX_TRACKED:
            # The keys are attacker-supplied, so the map cannot grow freely.
            cutoff = now - RECORD_INTERVAL
            for stale in [key for key, seen in _recorded.items() if seen < cutoff]:
                del _recorded[stale]
            if len(_recorded) >= _MAX_TRACKED:
                _recorded.clear()
        _recorded[ip] = now
        return True


def drip_delay(data: bytes) -> float:
    """Per-byte pacing that spreads `data` across the whole drip window.

    tarpit's own auto-pacing floors the gap at TARPIT_BYTE_DELAY, which is right
    for a 19-byte handshake and wrong here: a kilobyte of art at 1.5s a byte
    overruns the deadline twenty-fold, and the deadline flush then dumps almost
    all of it at once. Passing the rate explicitly makes the picture draw itself
    over the full two minutes instead of appearing in one lump at the end.
    """
    return DRIP_SECONDS / max(len(data), 1)


def enabled() -> bool:
    return os.getenv("HONEYPOT_RICKROLL", "1").strip().lower() not in (
        "0", "false", "no", "off")


def banner() -> bytes:
    """The art, CRLF-terminated and ready to write to a socket.

    Empty when the file is missing or disabled, which callers treat as "just
    close the connection" -- the behaviour before this existed. A honeypot must
    not fall over because a joke did.
    """
    global _tried, _rendered
    if _tried:
        return _rendered
    with _lock:
        if _tried:
            return _rendered
        _tried = True
        if not enabled():
            return _rendered
        try:
            text = ART_FILE.read_text(encoding="utf-8")[:MAX_BYTES]
        except OSError:
            return _rendered
        # The repository pins this file to LF (see .gitattributes). A raw
        # socket has no line discipline to translate it, so a bare LF drops a
        # line without returning the carriage and the art walks off the right
        # edge of the terminal.
        _rendered = text.replace("\r\n", "\n").replace("\n", "\r\n").encode(
            "utf-8", "replace")
    return _rendered
