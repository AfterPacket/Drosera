#!/usr/bin/env python3
"""Check which logins succeed.

Two ways to get this wrong, and they fail in opposite directions. Accept
everything and one probe identifies the honeypot; refuse too much and real
attackers never reach the shell, which is where everything worth recording
happens. These pin both edges.

The observed probe is included by name: `charles:charles` followed by
`345gs5662d34:345gs5662d34`, where accepting both ended the engagement.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import credentials  # noqa: E402


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return 0 if condition else 1


def main():
    bad = 0
    accepts = credentials.accepts

    # --- the probe that started this -------------------------------------
    bad += check("the real guess is accepted", accepts("charles", "charles"))
    bad += check("the accept-all probe is refused",
                 not accepts("345gs5662d34", "345gs5662d34"))
    bad += check("the probe string is refused as a password alone",
                 not accepts("root", "345gs5662d34"))
    bad += check("the probe string is refused as a username alone",
                 not accepts("345gs5662d34", "password"))

    # --- what a weak box actually falls to -------------------------------
    for username, password in [
        ("root", "root"), ("root", "123456"), ("root", "password"),
        ("root", "toor"), ("admin", "admin"), ("admin", "admin123"),
        ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("test", "test"),
        ("root", "vizxv"), ("root", "xc3511"), ("user", "user123"),
        ("oracle", "oracle"), ("git", "git"), ("root", ""),
        ("root", "letmein"), ("root", "qwerty"), ("root", "1qaz2wsx"),
    ]:
        bad += check(f"accepts {username}:{password or '<empty>'}",
                     accepts(username, password))

    # --- username-derived passwords, most of any spray list --------------
    bad += check("accepts username with digits appended",
                 accepts("charles", "charles123"))
    bad += check("accepts username with punctuation appended",
                 accepts("deploy", "deploy!"))
    bad += check("case does not matter", accepts("Admin", "ADMIN"))

    # --- generated strings, which is the thing being defended against ----
    for password in ["a8x2k9q4m1", "zk4m2p8x7q", "9f3k2m8x1p",
                     "x7k2m9p4q8a", "345gs5662d34"]:
        bad += check(f"refuses generated-looking {password}",
                     not accepts("root", password))

    # --- and the false-positive edge: real people pick bad passwords -----
    bad += check("a short mixed password is still plausible",
                 accepts("root", "abc123"))
    bad += check("a word with a year is plausible",
                 accepts("root", "password2024"),
                 "someone's actual password, not a generator's")
    bad += check("letters only are never treated as generated",
                 accepts("root", "correcthorsebattery"))
    bad += check("digits only are never treated as generated",
                 accepts("root", "8675309123"))

    # --- the opt-out --------------------------------------------------
    bad += check("looks_generated is what draws the line",
                 credentials.looks_generated("345gs5662d34")
                 and not credentials.looks_generated("password123"))

    print()
    print("all checks passed" if not bad else f"{bad} check(s) failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
