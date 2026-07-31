"""Which logins succeed, and which are refused.

Accepting every credential is the easiest way there is to be identified as a
honeypot, and it costs nothing to probe for. A scanner tries a plausible
credential, then one that cannot exist on any real machine:

    charles:charles                  <- a real guess
    345gs5662d34:345gs5662d34        <- a guess nobody has

If both succeed the server accepts everything, so it is not a server. That is
exactly what happened here: both were accepted, the session ended 2.8 seconds
later, and the address never came back except to be tarpitted. Everything the
honeypot exists to observe happens after the login, so failing this check
forfeits the entire engagement.

The rule below is the one a real neglected box follows: it has a weak password,
and that is the password that works. Common and guessable credentials are
accepted, because those are what a genuinely compromised host would fall to.
Machine-generated strings are refused, because no administrator ever set one as
their root password -- which is precisely why a prober picks one.

Set HONEYPOT_ACCEPT_ANY_PASSWORD=1 to restore the previous accept-everything
behaviour.
"""

import os
import re

ACCEPT_ANY = os.getenv("HONEYPOT_ACCEPT_ANY_PASSWORD", "0").strip().lower() in (
    "1", "true", "yes", "on")

# Credentials published in scanner tooling specifically to detect accept-all
# servers. Refused by name as well as by shape, so a probe that happens to look
# ordinary is still caught.
KNOWN_PROBES = {
    "345gs5662d34",
}

# What a weak account actually looks like. Anything here is accepted, because a
# host that falls to a password spray falls to one of these.
COMMON_PASSWORDS = {
    "", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "1234567890", "0000", "00000000", "111111", "121212", "654321", "666666",
    "888888", "abc123", "a123456", "123123", "qwerty", "qwerty123", "qwertyuiop",
    "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "asdfgh", "zxcvbnm",
    "password", "password1", "password123", "passw0rd", "pass", "pass123",
    "admin", "admin1", "admin123", "administrator", "root", "root123",
    "toor", "letmein", "welcome", "welcome1", "changeme", "default",
    "guest", "test", "test123", "user", "user123", "demo", "oracle",
    "postgres", "mysql", "ftpuser", "ubuntu", "raspberry", "pi",
    "support", "service", "system", "manager", "operator", "backup",
    "monitor", "nagios", "zabbix", "jenkins", "docker", "git", "deploy",
    "server", "linux", "unix", "debian", "centos", "redhat",
    "iloveyou", "dragon", "monkey", "sunshine", "princess", "football",
    "baseball", "master", "shadow", "superman", "trustno1", "secret",
    "hello", "hello123", "love", "freedom", "whatever", "starwars",
    "vizxv", "xc3511", "juantech", "anko", "xmhdipc", "seiko2005",
    "jvbzd", "hi3518", "klv123", "cat1029", "ivdev", "ipcam_rt5350",
}

# A password that is letters-and-digits, long, and matches nothing anyone would
# choose. Deliberately narrow: the cost of refusing a real attacker's guess is
# losing the session, so the shape has to be unmistakable.
_GENERATED = re.compile(r"^(?=.*[a-z])(?=.*\d)[a-z0-9]{9,}$", re.I)


def looks_generated(password: str) -> bool:
    """True for strings that read as output from a random generator.

    Requires letters and digits mixed through at least nine characters with no
    separator of any kind. `Summer2024` fails it on length shape, `admin123`
    fails on being in the common list first, `345gs5662d34` matches.
    """
    if not _GENERATED.match(password or ""):
        return False
    # A recognisable word at the front is someone's bad password, not a
    # generator's output: `password123`, `charles2019`, `ubuntu1234`.
    stem = re.sub(r"\d+$", "", password).lower()
    return not (len(stem) >= 4 and stem in COMMON_PASSWORDS)


def accepts(username: str, password: str) -> bool:
    """Whether this login should succeed."""
    if ACCEPT_ANY:
        return True

    username = (username or "").strip()
    password = password or ""

    # Named probes never work, whatever shape they are.
    if username.lower() in KNOWN_PROBES or password.lower() in KNOWN_PROBES:
        return False

    if password.lower() in COMMON_PASSWORDS:
        return True

    # The classic: the account name as its own password. Accepted only when the
    # name itself is not generated, or the probe above walks straight through
    # this rule -- both halves of `345gs5662d34:345gs5662d34` are equal too.
    if password and password.lower() == username.lower():
        return not looks_generated(password)

    # username + digits, which is most of what a spray list contains.
    stem = re.sub(r"[0-9!@#$%^&*_.-]+$", "", password).lower()
    if stem and username and stem == username.lower():
        return True

    return not looks_generated(password)
