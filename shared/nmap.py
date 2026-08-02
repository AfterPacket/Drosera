"""Detect nmap scans and reverse-scan the attacker.

When detected, scan the attacker's machine back to learn what's there, then store
the results in loot so an operator can see what Drosera learned about them.

Returns fake results showing Drosera's actual ports (22 ssh, 23 telnet, etc.) so
the attacker gets plausible data about *this* deployment, not a generic response.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

NMAP_PATTERNS = re.compile(
    r"(nmap|NSE|Nmap Scripting|nmap-user-agent|nmap-"
    r"|nping|ndiff|zenmap)",
    re.IGNORECASE,
)

NMAP_PROBE_PATHS = [
    "/nmap-probe-",
    "/.nmap-probe",
    "/nmap.html",
    "/.well-known/nmap",
]

# Ports Drosera actually listens on (match docker-compose.yml)
HONEYPOT_PORTS = {
    22: "ssh",
    23: "telnet",
    25: "smtp",
    3306: "mysql",
    445: "smb",
    3389: "rdp",
    21: "ftp",
    80: "http",
    443: "https",
}

OPEN_PORTS = list(HONEYPOT_PORTS.keys())


def is_nmap_useragent(user_agent: Optional[str]) -> bool:
    """Check if User-Agent looks like nmap."""
    if not user_agent:
        return False
    return bool(NMAP_PATTERNS.search(user_agent))


def is_nmap_probe_path(path: str) -> bool:
    """Check if request path looks like an nmap probe."""
    return any(probe in path.lower() for probe in NMAP_PROBE_PATHS)


def scan_attacker(attacker_ip: str, timeout: int = 10) -> Dict[str, any]:
    """Scan the attacker's machine using nmap if available.

    Returns a dict with:
    - ip: their address
    - timestamp: when scanned
    - ports_open: list of (port, service) tuples that responded
    - ports_closed: list of ports that rejected
    - os_guess: (name, confidence) if detected
    - error: if nmap failed

    If nmap is not installed, returns a simulated result based on common
    attacker infrastructure (trying to be realistic but not expose anything).
    """
    result: Dict[str, any] = {
        "ip": attacker_ip,
        "timestamp": time.time(),
        "ports_open": [],
        "ports_closed": [],
        "os_guess": None,
        "error": None,
    }

    # Try to use nmap if available
    try:
        output = subprocess.run(
            ["nmap", "-sV", "-O", "--osscan-guess", "-T3",
             "--max-retries", "1", attacker_ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        # Parse nmap output
        for line in output.stdout.split("\n"):
            # Port lines: "22/tcp open ssh"
            match = re.match(r"(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)", line)
            if match:
                port = int(match.group(1))
                state = match.group(2)
                service = match.group(3)
                if state == "open":
                    result["ports_open"].append((port, service))
                else:
                    result["ports_closed"].append(port)

            # OS line: "OS details: Linux 5.10 - 5.19"
            if "OS details:" in line:
                result["os_guess"] = line.split("OS details:")[1].strip()

        return result

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        result["error"] = str(e)

    # Fallback: simulate common attacker ports (if nmap not available)
    # Assume they're running a typical scanning rig: SSH, some web services
    common_open = [22, 80, 443, 8080]
    result["ports_open"] = [(port, "ssh" if port == 22 else "http") for port in common_open]
    result["ports_closed"] = [p for p in range(1, 1025) if p not in common_open]

    return result


def store_scan(storage_dir: Path, attacker_ip: str, scan: Dict[str, any]) -> bool:
    """Store the scan result in loot for the operator to review."""
    try:
        loot_dir = storage_dir / "loot"
        loot_dir.mkdir(parents=True, exist_ok=True)

        # Filename: nmap-<ip>-<timestamp>.json
        filename = f"nmap-{attacker_ip}-{int(scan['timestamp'])}.json"
        path = loot_dir / filename

        # Add Drosera's ports to the result so the operator knows what they saw
        scan["honeypot_ports"] = HONEYPOT_PORTS
        scan["fake_result_for_attacker"] = {
            "open_ports": [
                {"port": port, "service": service}
                for port, service in HONEYPOT_PORTS.items()
            ]
        }

        path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False


def fake_nmap_result(attacker_ip: str, target_port: Optional[int] = None) -> str:
    """Return a fake nmap result for the attacker to see.

    Shows Drosera's actual ports as open, making the scan look successful
    and plausible.
    """
    lines = [
        f"Starting Nmap 7.92 ( https://nmap.org ) at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Nmap scan report for {attacker_ip}",
        "Host is up (0.0024s latency).",
        "Not shown: 65530 filtered ports",
        "PORT      STATE SERVICE",
    ]

    for port in sorted(OPEN_PORTS):
        service = HONEYPOT_PORTS.get(port, "unknown")
        lines.append(f"{port}/tcp    open    {service}")

    lines.extend([
        "",
        "OS detection performed. Please be sure you have performed a ping scan first.",
        "Nmap done at {} -- 1 IP address scanned in 0.15 seconds".format(
            time.strftime('%Y-%m-%d %H:%M:%S')
        ),
    ])

    return "\n".join(lines)
