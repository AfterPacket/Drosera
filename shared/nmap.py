"""Recognise an nmap probe. Detection only -- nothing here answers it.

NOTHING IN THIS MODULE OPENS A SOCKET OR RUNS A PROCESS, and it must stay that
way. It is named for the tool it detects, not for one it runs:

  - AUTHORIZATION.md §2 attests that the deployment is passive and targets no
    third-party system; §7 says the architecture makes scanning back impossible
    from this box. Both are statements an operator may have to stand behind in
    front of a hosting provider or a CERT.
  - The connecting address is very often a compromised third party rather than
    the attacker, so a scan back is a live port scan aimed at another victim.
  - It could not work here anyway: egress from honeypot-internal is dropped at
    the host firewall, `nmap` is in none of the images, and OS fingerprinting
    needs CAP_NET_RAW which `cap_drop: [ALL]` removes. Every call would fall
    through to a fabricated result -- and a fabricated port scan written to
    storage/loot/ is indistinguishable from a real one in the evidence bundle
    that /api/export/<ip> hands to an abuse desk.

shared/fakeshell.py `_cmd_nmap` reached the same conclusion for the fake shell's
`nmap` command and answers with a generated report. Callers that want to answer
a probe generate the report at the call site, in the protocol the probe arrived
on; this module only says whether one arrived.
"""

from __future__ import annotations

import re
from typing import Optional

# Word-bounded on purpose. An unbounded, case-insensitive "NSE" also matches
# "license", "consent", "AdSense" and "nonsense", which between them cover a
# large share of ordinary crawler User-Agents -- and a false positive here
# scores a real visitor as a scanner. nmap's own HTTP User-Agent is
# "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
# which the bounded form still matches twice over.
NMAP_PATTERNS = re.compile(
    r"\b(nmap|nse|nping|ndiff|zenmap)\b",
    re.IGNORECASE,
)

NMAP_PROBE_PATHS = [
    "/nmap-probe-",
    "/.nmap-probe",
    "/nmap.html",
    "/.well-known/nmap",
]


def is_nmap_useragent(banner: Optional[str]) -> bool:
    """Whether a User-Agent or protocol banner names nmap.

    Works on any text the client sent first -- an HTTP User-Agent, an SSH
    version string, a telnet service probe -- because nmap identifies itself
    the same way in all of them.
    """
    if not banner:
        return False
    return bool(NMAP_PATTERNS.search(banner))


def is_nmap_probe_path(path: str) -> bool:
    """Whether an HTTP request path looks like an nmap NSE probe.

    Paths only. A telnet or SSH client sends no request path, so callers on
    those services want is_nmap_useragent() against the banner instead -- this
    one can only ever return False for them.
    """
    return any(probe in path.lower() for probe in NMAP_PROBE_PATHS)
