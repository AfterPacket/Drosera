#!/usr/bin/env python3
"""Check the ATT&CK mapping stays consistent with the scoring table.

The mapping exists twice -- shared/scoring.py for the Python services and
web/lib/drosera.php for the web tier -- because the two tiers share no code.
Two copies of a table drift, and the drift is invisible: a technique that
disappears from one side just stops appearing in the chart for that service,
which reads as "attackers did not do that" rather than as a bug.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import scoring  # noqa: E402

PHP = ROOT / "web" / "lib" / "drosera.php"


def php_techniques():
    """Parse the const TECHNIQUES block out of the PHP source."""
    text = PHP.read_text(encoding="utf-8")
    block = re.search(r"const TECHNIQUES = \[(.*?)\n\];", text, re.S)
    if not block:
        return {}
    found = {}
    for event, ident, name in re.findall(
            r"'([A-Z_0-9]+)'\s*=>\s*\['([^']+)',\s*'([^']+)'\]", block.group(1)):
        found[event] = (ident, name)
    return found


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return 0 if condition else 1


def main():
    bad = 0
    php = php_techniques()

    bad += check("the PHP table parses", bool(php), "found no TECHNIQUES block")

    # Every mapped event must be a real event type, or it maps nothing.
    unknown = sorted(set(scoring.TECHNIQUES) - set(scoring.SCORES))
    bad += check("every mapped event exists in SCORES", not unknown, unknown)

    unknown_php = sorted(set(php) - set(scoring.SCORES))
    bad += check("every PHP-mapped event exists in SCORES", not unknown_php,
                 unknown_php)

    # Where both tiers map the same event, they must agree -- otherwise the
    # same behaviour is two different techniques depending on which port it
    # arrived on.
    disagreements = [
        (event, scoring.TECHNIQUES[event], php[event])
        for event in sorted(set(php) & set(scoring.TECHNIQUES))
        if scoring.TECHNIQUES[event] != php[event]
    ]
    bad += check("the two tiers agree where they overlap", not disagreements,
                 disagreements)

    # Technique ids have a shape; a typo here is silent in every chart.
    malformed = sorted(
        ident for ident, _ in scoring.TECHNIQUES.values()
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", ident))
    bad += check("technique ids are well formed", not malformed, malformed)

    # The events worth mapping most are the ones an operator would look for.
    for event in ("CREDENTIAL_ATTEMPT", "WEBSHELL_CMD", "LOADER_URL",
                  "PERSISTENCE_ATTEMPT", "REVERSE_SHELL", "FILE_UPLOAD"):
        bad += check(f"{event} is mapped", event in scoring.TECHNIQUES)

    # And the ones that are not techniques stay unmapped, or the chart becomes
    # a description of this table rather than of the traffic.
    for event in ("CONNECTION_ANY", "TARPIT_ENGAGED"):
        bad += check(f"{event} is deliberately unmapped",
                     event not in scoring.TECHNIQUES)

    bad += check("get_technique returns None for an unknown event",
                 scoring.get_technique("NOT_A_REAL_EVENT") is None)
    bad += check("get_technique returns the pair for a known one",
                 scoring.get_technique("CREDENTIAL_ATTEMPT") == ("T1110", "Brute Force"))

    print()
    print("all checks passed" if not bad else f"{bad} check(s) failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
