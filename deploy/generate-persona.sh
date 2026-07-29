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

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found; cannot generate a persona." >&2
    echo "  The honeypot still runs on the defaults published in this repo," >&2
    echo "  which is exactly what you do not want on a live host." >&2
    exit 1
fi

mkdir -p "$(dirname "$TARGET")" || exit 1

# Written to a temporary file first: a half-written persona.json is worse than
# none, because both readers fall back per-key and you would get a machine that
# is half yours and half the published default.
TMP="${TARGET}.tmp.$$"
trap 'rm -f "$TMP"' EXIT

if ! python3 - "$TMP" <<'PY'
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

STREETS = ["Commerce Drive", "Lakeview Parkway", "Foundry Street", "Kingsway",
           "Aldgate Road", "Riverside Avenue", "Beacon Court", "Mill Lane",
           "Cedar Boulevard", "Quarry Road", "Innovation Way", "Hartley Street"]
# (city, state, ZIP prefix, area code). The area code is carried so the phone
# number in the footer agrees with the address above it -- an Austin address
# beside a Denver number is the kind of detail that reads as fake.
CITIES = [("Austin", "TX", "787", "512"), ("Denver", "CO", "802", "303"),
          ("Raleigh", "NC", "276", "919"), ("Portland", "OR", "972", "503"),
          ("Columbus", "OH", "432", "614"), ("Tampa", "FL", "336", "813"),
          ("Boise", "ID", "837", "208"), ("Madison", "WI", "537", "608")]

ENTITIES = ["LLC", "Inc.", "Ltd.", "Group", "Partners", "Co."]

# One tagline per sector, so the headline agrees with the company name rather
# than every deployment claiming to be an IT consultancy.
TAGLINES = {
    "Digital Solutions": ("Digital Solutions for Modern Business",
                          "web development, digital strategy, cloud migration"),
    "Systems Group":     ("Systems Engineering That Scales",
                          "systems integration, infrastructure, automation"),
    "Technologies":      ("Technology That Works the Way You Do",
                          "software development, integration, IT strategy"),
    "Consulting":        ("Practical Consulting for Growing Teams",
                          "IT consulting, advisory, digital transformation"),
    "Data Services":     ("Data Infrastructure You Can Rely On",
                          "data warehousing, analytics, ETL, reporting"),
    "IT Partners":       ("Your IT Department, Without the Overhead",
                          "managed IT, helpdesk, IT support, outsourcing"),
    "Networks":          ("Networks Built for Uptime",
                          "network design, connectivity, SD-WAN, monitoring"),
    "Managed Services":  ("Managed Services, Measured Results",
                          "managed services, monitoring, backup, support"),
}

DB_USERS = ["devuser", "wpuser", "appuser", "webadmin", "deploy", "svc_web"]
DB_SUFFIX = ["_prod", "_live", "_db", "_main", "_wp"]

# Password shapes that look like something a hurried admin actually typed.
PW_WORDS = ["Summer", "Winter", "Staging", "Deploy", "Backup", "Server",
            "Admin", "Launch", "Secure", "Prod"]
PW_SYMBOLS = ["!", "#", "$", "@", "%", "&"]

DOCUMENTS = ["strategic-plan-{y}.pdf", "invoice-template.xlsx", "org-chart.pdf",
             "onboarding-checklist.docx", "q{q}-forecast.xlsx", "msa-signed.pdf",
             "network-diagram-{y}.png", "pricing-sheet-{y}.pdf",
             "incident-postmortem.docx", "vendor-list.csv"]


def password():
    return "{}{}{}{}".format(
        rng.choice(PW_WORDS), rng.randint(2020, 2025),
        rng.choice(PW_SYMBOLS), rng.choice(["", str(rng.randint(1, 99))]),
    )


def token(alphabet, length):
    return "".join(rng.choice(alphabet) for _ in range(length))

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

word = rng.choice(WORDS)
sector = rng.choice(SECTORS)
company = f"{word} {sector}"
company_short = f"{word} {sector.split()[0]}"
slug = word.lower()
domain = f"{company_short.replace(' ', '').lower()}.example"

php = rng.choice(PHP)
db = rng.choice(MYSQL)

db_user = rng.choice(DB_USERS)
db_name = slug + rng.choice(DB_SUFFIX)
db_password = password()
mail_password = password()

# Honeytokens. Planted in the fake .env, wp-config and the homepage comments;
# nothing accepts them. Uniqueness is the whole value: a token that turns up in
# a paste dump or a credential-stuffing run names the box it was scraped from.
abbrev = (word[0] + "".join(c for c in word[1:].lower() if c not in "aeiou"))[:3].lower()
honeytoken = f"sk-{abbrev}-test-{token('0123456789abcdef', 16)}"
aws_key = "AKIA" + token("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
aws_key_staging = "AKIA" + token("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)

city, state, zip3, area = rng.choice(CITIES)
address = "{} {}, Suite {}, {}, {} {}{:02d}".format(
    rng.randint(100, 4999), rng.choice(STREETS), rng.randint(100, 940),
    city, state, zip3, rng.randint(1, 99),
)
# 555-01xx is the block reserved for fiction, so the number cannot ring anyone.
phone = "({}) 555-{:04d}".format(area, rng.randint(100, 199))
entity = rng.choice(ENTITIES)
tagline, keywords = TAGLINES.get(
    sector, ("Expert IT Solutions for Modern Business",
             "IT consulting, managed services, infrastructure"))

# The uploads directory and the documents in it. Dated consistently: a file
# called strategic-plan-2024.pdf sitting under uploads/2019/03 is a tell.
upload_year = rng.randint(2022, 2025)
upload_month = "{:02d}".format(rng.randint(1, 12))
documents = [
    doc.format(y=upload_year, q=rng.randint(1, 4))
    for doc in rng.sample(DOCUMENTS, rng.randint(1, 3))
]
backup_name = "db-backup-{}-{}-{:02d}.sql.gz".format(
    upload_year, upload_month, rng.randint(1, 28))

# Shell history is a strong tell: an attacker who sees the same eight commands
# on two unrelated hosts knows what both of them are.
history_pool = [
    "cd /var/www/html", "ls -la", "df -h", "free -m", "top",
    "tail -f /var/log/nginx/error.log", "tail -100 /var/log/syslog",
    f"systemctl restart php{php.rsplit('.', 1)[0]}-fpm",
    "systemctl status nginx", "sudo apt-get update", "sudo apt-get upgrade",
    "vim wp-config.php", "nano /etc/nginx/nginx.conf", "crontab -l",
    "docker ps", "git pull", "netstat -tulpn", "journalctl -xe",
    f"mysql -u {db_user} -p {db_name}",
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
    "company_short": company_short,
    "company_domain": domain,
    "company_slug": slug,
    "company_address": address,
    "company_founded": rng.randint(2009, 2019),
    "company_phone": phone,
    "company_entity": entity,
    "company_tagline": tagline,
    "company_keywords": keywords,
    "db_name": db_name,
    "db_user": db_user,
    "db_password": db_password,
    "honeytoken_key": honeytoken,
    "aws_access_key_id": aws_key,
    "aws_access_key_id_staging": aws_key_staging,
    "mail_password": mail_password,
    "staging_ip": f"10.0.{rng.randint(0, 40)}.{rng.randint(2, 250)}",
    "document_pool": documents,
    "backup_name": backup_name,
    "upload_path": [str(upload_year), upload_month],
    "fs_seed": rng.randrange(1, 2 ** 31),
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

print(f"  company   {persona['company_name']} ({persona['company_domain']})")
print(f"  ssh       {persona['ssh_banner']}")
print(f"  http      {persona['http_server']} / PHP {persona['php_version']}")
print(f"  database  {persona['db_user']}@{persona['db_name']}")
print(f"  hostnames {', '.join(persona['hostname_pool'][:4])} ...")
print(f"  tokens    {persona['honeytoken_key']}")
print(f"            {persona['aws_access_key_id']}")
PY
then
    echo "persona generation failed; ${TARGET} left unchanged." >&2
    exit 1
fi

# Sanity-check what we just wrote before it replaces a working persona.
if ! python3 -c "
import json, sys
required = ['ssh_banner', 'company_name', 'company_domain', 'db_name',
            'honeytoken_key', 'hostname_pool', 'user_pool', 'seeded_history',
            'fs_seed', 'upload_path',
            # Site copy. Absent from personas generated before these existed,
            # and the web tier silently falls back to the shipped defaults --
            # which is exactly the shared fingerprint the persona exists to
            # avoid, so it is worth failing loudly on instead.
            'company_phone', 'company_entity', 'company_tagline',
            'company_keywords']
data = json.load(open(sys.argv[1], encoding='utf-8'))
missing = [k for k in required if not data.get(k)]
if missing:
    sys.exit('incomplete persona, missing: ' + ', '.join(missing))
" "$TMP"; then
    echo "generated persona failed validation; ${TARGET} left unchanged." >&2
    exit 1
fi

mv "$TMP" "$TARGET" || exit 1
chmod 0644 "$TARGET"
echo
echo "Wrote ${TARGET} (gitignored)."
echo
echo "The tokens above are honeytokens: planted in the fake .env, wp-config and"
echo "the homepage comments, accepted by nothing. If one ever surfaces in a"
echo "credential dump or a login attempt elsewhere, it was scraped from here."
echo "Back this file up -- regenerating changes the machine attackers see."
echo
echo "Restart the services to apply:  docker compose up -d"
