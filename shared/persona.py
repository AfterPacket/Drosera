"""Per-deployment identity of the machine this honeypot pretends to be.

The engine is public; the persona should not be. Every constant that an
attacker can observe and compare against a published default is a fingerprint:
the SSH version string, the hostname and kernel pools, the shell history, the
company name on the website. Stock Cowrie is trivially identified precisely
because almost nobody changes its defaults, and the same fate is available to
anything that ships its persona as source constants.

So the persona lives in a generated, gitignored JSON file. The published code
tells an attacker how the honeypot works and nothing about how *yours* looks,
and two deployments of the same release are two different machines.

Generate one with:

    ./deploy/generate-persona.sh

Absent the file, the built-in defaults below are used, so a fresh clone runs.
Those defaults are public, which is exactly why a real deployment should not
keep them -- `deploy/preflight.sh` warns when it finds none.
"""

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

PERSONA_FILE = Path(os.getenv("PERSONA_FILE", "/persona/persona.json"))

# Public defaults. Enough to look plausible out of the box, and deliberately
# the first thing a real deployment replaces.
DEFAULTS: Dict[str, Any] = {
    "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "ftp_banner": "ProFTPD 1.3.5e Server (Debian)",
    "smtp_software": "Postfix (Ubuntu)",
    "http_server": "Apache/2.4.41 (Ubuntu)",
    "php_version": "7.4.33",
    "mysql_version": "5.7.38-0ubuntu0.22.04.1",
    "company_name": "Meridian Digital Solutions",
    "hostname_pool": [
        "prod-web-01", "prod-web-02", "prod-db-01", "prod-cache-01",
        "mail-srv-01", "api-gateway-01", "proxy-01", "app-node-03",
        "backup-srv", "monitoring-01", "vpn-gateway", "srv-colo-04",
    ],
    "kernel_pool": [
        "5.15.0-86-generic", "5.15.0-91-generic", "5.10.0-21-amd64",
        "5.4.0-150-generic", "4.19.0-23-amd64", "6.1.0-13-amd64",
    ],
    "os_pool": [
        "Ubuntu 22.04.3 LTS", "Ubuntu 20.04.6 LTS",
        "Debian GNU/Linux 11 (bullseye)", "Debian GNU/Linux 12 (bookworm)",
        "CentOS Linux 7 (Core)", "AlmaLinux 8.9",
    ],
    "user_pool": [
        ["jmarsh", "/home/jmarsh"], ["dkowalski", "/home/dkowalski"],
        ["rchen", "/home/rchen"], ["aokafor", "/home/aokafor"],
        ["tbergman", "/home/tbergman"], ["lnguyen", "/home/lnguyen"],
    ],
    "seeded_history": [
        "cd /var/www/html", "ls -la", "tail -f /var/log/nginx/error.log",
        "systemctl restart php7.4-fpm", "mysql -u devuser -p meridian_prod",
        "df -h", "sudo apt-get update", "vim wp-config.php",
    ],
    "last_login_from": "10.0.1.9",
    "last_login_at": "Mon Jan 15 08:14:02 2024",
}

_loaded: Dict[str, Any] = {}
_lock = threading.Lock()
_tried = False


def _load() -> Dict[str, Any]:
    global _tried
    if _tried:
        return _loaded
    with _lock:
        if _tried:
            return _loaded
        _tried = True
        try:
            if PERSONA_FILE.is_file():
                data = json.loads(PERSONA_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    _loaded.update(data)
        except (OSError, json.JSONDecodeError):
            # A malformed persona must not take the honeypot down; the
            # defaults are a working fallback.
            pass
    return _loaded


def get(key: str, default: Any = None) -> Any:
    value = _load().get(key)
    if value in (None, "", [], {}):
        return DEFAULTS.get(key, default)
    return value


def pool(key: str) -> List[Any]:
    value = get(key)
    return list(value) if isinstance(value, (list, tuple)) else []


def is_custom() -> bool:
    """True when a generated persona is in use rather than the public defaults."""
    return bool(_load())
