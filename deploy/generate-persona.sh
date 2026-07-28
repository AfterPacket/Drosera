#!/usr/bin/env bash
#
# Generate this deployment's persona: the machine the honeypot pretends to be.
#
# The engine is public, so every observable constant shipped as source is a
# fingerprint. Anyone with the repository can compare a live host against the
# defaults and identify it in a few lines. This writes a randomised persona so
# that two deployments of the same release look like two different machines.
#
#   ./deploy/generate-persona.sh            # generate if absent
#   ./deploy/generate-persona.sh --force    # replace an existing one
#
# The result is gitignored. Keep a backup if you care about consistency across
# rebuilds -- an attacker who saw "prod-db-01 running CentOS 7" last week and
# finds a different machine on the same address this week has learnt something.

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${REPO_DIR}/persona/persona.json"

if [ -f "$TARGET" ] && [ "${1:-}" != "--force" ]; then
    echo "persona already exists at ${TARGET}"
    echo "  --force to replace it (changes the machine attackers see)"
    exit 0
fi

mkdir -p "$(dirname "$TARGET")"

python3 - "$TARGET" <<'PY'
import json
import random
import sys

rng = random.SystemRandom()

# Pools deliberately wider than any single deployment uses. The point is that
# your six hostnames are not the same six as everyone else's.
ROLES = ["web", "db", "cache", "mail", "api", "proxy", "app", "backup",
         "monitor", "vpn", "srv", "node", "gw", "store", "auth", "ns"]
QUALIFIERS = ["prod", "prd", "live", "int", "core", "edge", "dc1", "dc2",
              "eu", "us", "vm", "host", "srv", ""]

KERNELS = [
    "5.15.0-{}-generic", "5.4.0-{}-generic", "6.8.0-{}-generic",
    "5.10.0-{}-amd64", "6.1.0-{}-amd64", "4.19.0-{}-amd64",
    "3.10.0-{}.el7.x86_64",
]

DISTROS = [
    "Ubuntu 22.04.{} LTS", "Ubuntu 20.04.{} LTS", "Ubuntu 24.04.{} LTS",
    "Debian GNU/Linux 11 (bullseye)", "Debian GNU/Linux 12 (bookworm)",
    "CentOS Linux 7 (Core)", "AlmaLinux 8.{}", "Rocky Linux 9.{}",
]

OPENSSH = ["8.9p1", "8.2p1", "9.2p1", "9.6p1", "8.4p1", "7.4"]
SUFFIX = ["Ubuntu-3ubuntu0.6", "Ubuntu-4ubuntu0.11", "Debian-2+deb12u2",
          "Ubuntu-3ubuntu13.5", ""]

PHP = ["7.4.33", "8.1.2", "8.2.7", "7.4.3", "8.0.30"]
MYSQL = ["5.7.38-0ubuntu0.22.04.1", "8.0.35-0ubuntu0.22.04.1",
         "10.6.12-MariaDB-0ubuntu0.22.04.1", "5.7.41-log"]
HTTPD = ["Apache/2.4.41 (Ubuntu)", "Apache/2.4.52 (Ubuntu)",
         "nginx/1.18.0 (Ubuntu)", "nginx/1.22.1", "Apache/2.4.57 (Debian)"]

FIRST = ["j", "d", "r", "a", "t", "l", "m", "s", "k", "p", "c", "n", "e", "b"]
LAST = ["marsh", "kowalski", "chen", "okafor", "bergman", "nguyen", "rossi",
        "silva", "novak", "hassan", "muller", "dubois", "walsh", "ivanov",
        "tanaka", "andersen", "reyes", "kaur", "olsen", "petrov"]

WORDS = ["Meridian", "Northgate", "Clearwater", "Ironbridge", "Blackwood",
         "Redpoint", "Summit", "Harbour", "Kestrel", "Lantern", "Copper",
         "Foxglove", "Trellis", "Halcyon", "Pinnacle", "Alder"]
SECTORS = ["Digital Solutions", "Systems Group", "Technologies", "Consulting",
           "Data Services", "IT Partners", "Networks", "Managed Services"]

def hostname():
    qualifier = rng.choice(QUALIFIERS)
    role = rng.choice(ROLES)
    base = f"{qualifier}-{role}" if qualifier else role
    return f"{base}-{rng.randint(1, 9):02d}" if rng.random() < 0.75 else base

hostnames = list({hostname() for _ in range(rng.randint(8, 14))})
kernels = list({rng.choice(KERNELS).format(rng.randint(20, 160))
                for _ in range(rng.randint(4, 7))})
distros = list({rng.choice(DISTROS).format(rng.randint(1, 9))
                for _ in range(rng.randint(4, 6))})

users = []
for surname in rng.sample(LAST, rng.randint(5, 8)):
    name = rng.choice(FIRST) + surname
    users.append([name, f"/home/{name}"])

company = f"{rng.choice(WORDS)} {rng.choice(SECTORS)}"
php = rng.choice(PHP)
db = rng.choice(MYSQL)

# Shell history is a strong tell: an attacker who sees the same eight commands
# on two unrelated hosts knows what both of them are.
history_pool = [
    "cd /var/www/html", "ls -la", "df -h", "free -m", "top",
    "tail -f /var/log/nginx/error.log", "tail -100 /var/log/syslog",
    f"systemctl restart php{php.rsplit('.', 1)[0]}-fpm",
    "systemctl status nginx", "sudo apt-get update", "sudo apt-get upgrade",
    "vim wp-config.php", "nano /etc/nginx/nginx.conf", "crontab -l",
    "docker ps", "git pull", "netstat -tulpn", "journalctl -xe",
    f"mysql -u devuser -p {rng.choice(['app', 'wp', 'prod', 'main'])}_db",
    "certbot renew --dry-run", "du -sh /var/log/*",
]

persona = {
    "ssh_banner": (f"SSH-2.0-OpenSSH_{rng.choice(OPENSSH)}"
                   + (lambda s: f" {s}" if s else "")(rng.choice(SUFFIX))).strip(),
    "ftp_banner": rng.choice([
        "ProFTPD 1.3.5e Server (Debian)", "ProFTPD 1.3.6 Server",
        "vsFTPd 3.0.3", "Pure-FTPd",
    ]),
    "smtp_software": rng.choice(["Postfix (Ubuntu)", "Postfix (Debian/GNU)",
                                 "Exim 4.94.2", "Sendmail 8.15.2"]),
    "http_server": rng.choice(HTTPD),
    "php_version": php,
    "mysql_version": db,
    "company_name": company,
    "hostname_pool": sorted(hostnames),
    "kernel_pool": sorted(kernels),
    "os_pool": sorted(distros),
    "user_pool": users,
    "seeded_history": rng.sample(history_pool, rng.randint(6, 10)),
    "last_login_from": f"10.0.{rng.randint(0, 40)}.{rng.randint(2, 250)}",
    "last_login_at": "{} {} {:02d}:{:02d}:{:02d} {}".format(
        rng.choice(["Mon", "Tue", "Wed", "Thu", "Fri"]),
        rng.choice(["Jan", "Feb", "Mar", "Nov", "Dec"]),
        rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59),
        rng.choice([2024, 2025]),
    ),
}

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(persona, handle, indent=2)

print(f"  company   {persona['company_name']}")
print(f"  ssh       {persona['ssh_banner']}")
print(f"  http      {persona['http_server']}")
print(f"  hostnames {', '.join(persona['hostname_pool'][:4])} ...")
PY

chmod 0644 "$TARGET"
echo
echo "Wrote ${TARGET} (gitignored)."
echo "Restart the services to apply:  docker compose up -d"
