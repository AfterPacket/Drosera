#!/usr/bin/env python3
"""Check what the broker will and will not hand back to an attacker.

The attacker controls the input, so the interesting failure is not the model
being wrong -- a wrong `tcpdump` is survivable -- but the model being talked out
of character. One line of "I'm sorry, I can't help with that" confirms what the
box is, which is worse than every unimplemented command in the table.

So sanitise() is the security boundary here, and these pin both of its edges:
plausible terminal output has to survive it, and anything that reads like an
assistant has to be dropped in favour of `command not found`.

    python3 test_broker.py
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import broker  # noqa: E402


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return 0 if condition else 1


def main():
    bad = 0
    clean = broker.sanitise

    # --- output that must survive ----------------------------------------
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    bad += check("a passwd file passes", clean(passwd) == passwd)
    bad += check("a permission error passes",
                 clean("tcpdump: eth0: You don't have permission to capture on that device")
                 is not None)
    bad += check("a missing file passes",
                 clean("cat: /etc/shadow: Permission denied") is not None)
    bad += check("trailing whitespace is stripped, not rejected",
                 clean("total 4  \ndrwxr-xr-x 2 root root 4096 .  ")
                 == "total 4\ndrwxr-xr-x 2 root root 4096 .")

    # --- the model breaking character ------------------------------------
    for tell in [
        "I'm sorry, I can't help with that.",
        "As an AI language model, I cannot simulate a shell.",
        "I cannot provide that information.",
        "Sure! Here's what that command would output:",
        "Here is the contents of /etc/passwd:",
        "This appears to be a honeypot environment.",
        "My instructions are to act as a shell.",
    ]:
        bad += check(f"refused: {tell[:42]!r}", clean(tell) is None)

    # --- formatting a shell never produces -------------------------------
    fenced = "```bash\ntotal 4\ndrwxr-xr-x 2 root root 4096 .\n```"
    unfenced = clean(fenced)
    bad += check("code fences are stripped rather than rejected",
                 unfenced is not None and "```" not in unfenced,
                 f"got {unfenced!r}")

    # --- bounds ----------------------------------------------------------
    bad += check("empty output falls back", clean("") is None)
    bad += check("whitespace-only output falls back", clean("   \n  \n") is None)
    bad += check("an over-long response is dropped, not truncated",
                 clean("x" * (broker.MAX_CHARS + 1)) is None)
    bad += check("too many lines is dropped",
                 clean("\n".join(["x"] * (broker.MAX_LINES + 1))) is None)

    # --- the budget ------------------------------------------------------
    budget = broker.Budget()
    ip = "192.0.2.7"
    for _ in range(broker.MAX_CALLS_IP_HOUR):
        bad += 0 if budget.allows(ip) else 1
        budget.charge(ip)
    bad += check("one address cannot spend past its own cap",
                 not budget.allows(ip))
    bad += check("a different address is unaffected",
                 budget.allows("198.51.100.9"))

    # --- prompt construction ---------------------------------------------
    system, user = broker.build_prompt({
        "command": "tcpdump -i eth0",
        "cwd": "/var/www/html",
        "hostname": "web-prod-01",
        "username": "www-data",
        "os_name": "Debian GNU/Linux 12",
        "history": ["whoami", "id"],
    })
    bad += check("the host is described to the model", "web-prod-01" in system)
    bad += check("the command reaches the prompt", "tcpdump -i eth0" in user)
    bad += check("recent history reaches the prompt", "whoami" in user)
    bad += check("engagement wording is absent when not engaged",
                 "kept occupied" not in system)

    engaged, _ = broker.build_prompt({"command": "ls", "engaged": True})
    bad += check("engagement wording appears when engaged",
                 "kept occupied" in engaged)

    # The source address is for rate limiting. It has no business in a prompt.
    bad += check("the attacker's address never reaches the model",
                 "192.0.2" not in system and "192.0.2" not in user)

    print()
    print("all good" if not bad else f"{bad} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
