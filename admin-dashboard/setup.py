#!/usr/bin/env python3
"""First-run setup for the Drosera dashboard.

Creates admin-config.json with a bcrypt password hash and a fresh TOTP secret,
and prints the enrolment QR code as terminal art. Run it once:

    docker compose run --rm admin-dashboard python3 setup.py

The config file is the only place these secrets live. It is never passed through
docker-compose environment variables.
"""

import getpass
import json
import os
import re
import sys
from pathlib import Path

import bcrypt
import pyotp
import qrcode

CONFIG_FILE = Path(os.getenv("ADMIN_CONFIG", "/app/config/admin-config.json"))
MIN_LENGTH = 16
ISSUER = "Drosera"


def fail(message: str) -> None:
    print(f"\n  error: {message}", file=sys.stderr)
    sys.exit(1)


def password_problems(password: str) -> list:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters (got {len(password)})")
    if not re.search(r"[a-z]", password):
        problems.append("needs a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("needs an uppercase letter")
    if not re.search(r"[0-9]", password):
        problems.append("needs a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("needs a symbol")
    return problems


def ascii_qr(payload: str) -> str:
    """Render the otpauth URI as half-block characters so it scans from a terminal."""
    code = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    code.add_data(payload)
    code.make(fit=True)
    matrix = code.get_matrix()

    lines = []
    for row in range(0, len(matrix), 2):
        upper = matrix[row]
        lower = matrix[row + 1] if row + 1 < len(matrix) else [False] * len(upper)
        line = ""
        for column in range(len(upper)):
            top, bottom = upper[column], lower[column]
            if top and bottom:
                line += "█"
            elif top:
                line += "▀"
            elif bottom:
                line += "▄"
            else:
                line += " "
        lines.append(line)
    return "\n".join(lines)


def main() -> None:
    print("\n  Drosera dashboard setup")
    print("  " + "-" * 48)

    if CONFIG_FILE.exists():
        print(f"\n  {CONFIG_FILE} already exists.")
        answer = input("  Overwrite it? This invalidates the current 2FA enrolment. [y/N] ")
        if answer.strip().lower() != "y":
            print("  Aborted. Nothing changed.")
            return

    if not sys.stdin.isatty():
        fail("setup.py needs an interactive terminal. Use: "
             "docker compose run --rm admin-dashboard python3 setup.py")

    username = input("\n  Admin username: ").strip()
    if not username or len(username) > 64:
        fail("username must be 1-64 characters")

    print(f"\n  Password must be >= {MIN_LENGTH} chars with upper, lower, digit, and symbol.")
    password = ""
    for _attempt in range(3):
        password = getpass.getpass("  Password: ")
        problems = password_problems(password)
        if problems:
            print("  Rejected: " + "; ".join(problems))
            continue
        if password != getpass.getpass("  Confirm password: "):
            print("  Passwords did not match.")
            continue
        break
    else:
        fail("too many failed attempts")

    print("\n  Hashing password (bcrypt, cost 12)...")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

    totp_secret = pyotp.random_base32()
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=ISSUER)

    allowed = input("\n  Allowed source IPs for the dashboard [127.0.0.1]: ").strip()
    allowed_ips = [item.strip() for item in allowed.split(",") if item.strip()] or ["127.0.0.1"]

    config = {
        "username": username,
        "password_hash": password_hash,
        "totp_secret": totp_secret,
        "allowed_ips": allowed_ips,
    }

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Write restricted from the outset -- never world-readable, even briefly.
    descriptor = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)

    print("\n  " + "=" * 60)
    print("  Scan this with Google Authenticator, Authy, or 1Password:\n")
    print(ascii_qr(uri))
    print(f"\n  If you cannot scan, enter this secret manually:\n\n      {totp_secret}\n")
    print("  " + "=" * 60)
    print(f"\n  Wrote {CONFIG_FILE} (mode 0600)")
    print("\n  IMPORTANT: store the secret above in your password manager now.")
    print("  There are no backup codes. Losing it means re-running this script,")
    print("  which requires shell access to the VPS.\n")
    print("  Start the dashboard, then tunnel to it:")
    print("      ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@your-vps")
    print("      open http://127.0.0.1:8443/\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(130)
