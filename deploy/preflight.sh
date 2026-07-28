#!/usr/bin/env bash
#
# Drosera preflight: static validation before you deploy anything.
#
# Every check here runs without starting a container, so it is safe to run on a
# laptop or on the VPS before `docker compose up`. It catches the class of bug
# that otherwise surfaces as a container restart-looping at 3am: syntax errors,
# broken compose interpolation, secrets about to be committed.
#
# Exits non-zero if any check fails. Warnings do not fail the run.
#
#   ./deploy/preflight.sh

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1

FAILED=0
WARNED=0

pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=$((FAILED + 1)); }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; WARNED=$((WARNED + 1)); }
head2() { printf '\n\033[1m%s\033[0m\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------- python syntax

head2 "Python syntax"

if have python3; then
    # ast.parse rather than compileall: compileall writes __pycache__, which
    # fails on a checkout the invoking user cannot write to and litters the tree
    # with root-owned directories when run under sudo. Parsing gives the same
    # answer and touches nothing. Every file is reported, not just the first.
    PY_SYNTAX_CHECK='
import ast, pathlib, sys
bad = []
for path in sorted(pathlib.Path(sys.argv[1]).rglob("*.py")):
    try:
        ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError as error:
        bad.append("%s:%s: %s" % (path, error.lineno, error.msg))
if bad:
    print("\n".join(bad))
    sys.exit(1)
'
    for dir in shared session-cam elastic intel admin-dashboard ssh-honey ftp-honey \
               telnet-honey smtp-honey mysql-honey smb-honey rdp-honey; do
        [ -d "$dir" ] || continue
        if out=$(python3 -c "$PY_SYNTAX_CHECK" "$dir" 2>&1); then
            pass "$dir"
        else
            fail "$dir"
            printf '%s\n' "$out" | sed 's/^/        /'
        fi
    done
else
    warn "python3 not found; skipped"
fi

# --------------------------------------------------------- undefined names

head2 "Python name resolution"

# ast.parse above proves the file is syntactically valid, which is not the same
# as correct: a missing import only fails when the function using it is called,
# so `tarpit.begin_hold(...)` inside an error path can sit undetected until an
# attacker triggers it in production. pyflakes catches exactly this class --
# undefined names and unused imports -- and nothing else, which makes it fast
# and free of style noise.
if have python3 && python3 -c "import pyflakes" 2>/dev/null; then
    if out=$(python3 -m pyflakes shared session-cam elastic intel admin-dashboard \
                 ssh-honey ftp-honey telnet-honey smtp-honey mysql-honey \
                 smb-honey rdp-honey 2>&1); then
        pass "no undefined names"
    else
        # Unused imports are noise here; undefined names are the point.
        undefined=$(printf '%s\n' "$out" | grep "undefined name" || true)
        if [ -n "$undefined" ]; then
            fail "undefined names found"
            printf '%s\n' "$undefined" | sed 's/^/        /'
        else
            pass "no undefined names"
            printf '%s\n' "$out" | grep -c "imported but unused" >/dev/null 2>&1 \
                && warn "$(printf '%s\n' "$out" | grep -c 'imported but unused') unused import(s)"
        fi
    fi
else
    warn "pyflakes not installed; undefined names will not be caught"
    warn "  pip3 install --user pyflakes"
fi

# -------------------------------------------------------- stdlib-only imports

head2 "Egress container dependencies"

# The intel container has internet access and installs no third-party packages,
# so everything it imports must resolve with stdlib alone. This broke once:
# shared/__init__.py imported every submodule eagerly, so `from shared import
# loot` pulled in identity.py and therefore redis, and the container
# crash-looped on a package it never calls.
#
# Poisoning sys.modules is the honest test -- it fails exactly where the
# container would, rather than passing because redis happens to be installed
# on the machine running preflight.
if have python3; then
    STDLIB_ONLY_CHECK='
import sys
for blocked in ("redis", "paramiko", "flask", "PIL", "pyte"):
    sys.modules[blocked] = None
sys.path.insert(0, ".")
import shared.loot, shared.alerting, shared.persona
'
    if out=$(python3 -c "$STDLIB_ONLY_CHECK" 2>&1); then
        pass "shared.loot / alerting / persona import without third-party packages"
    else
        fail "intel container would crash-loop: a stdlib-only import pulled in a dependency"
        printf '%s\n' "$out" | tail -5 | sed 's/^/        /'
    fi
else
    warn "python3 not found; skipped"
fi

# ------------------------------------------------------------------ php syntax

head2 "PHP syntax"

if have php; then
    found=0
    while IFS= read -r file; do
        found=1
        if out=$(php -l "$file" 2>&1); then
            pass "$file"
        else
            fail "$file"
            printf '%s\n' "$out" | sed 's/^/        /'
        fi
    done < <(find web -name '*.php' -type f 2>/dev/null | sort)
    [ "$found" -eq 0 ] && warn "no PHP files found"
else
    warn "php not installed locally; PHP is linted in the web image at build time"
fi

# ----------------------------------------------------------------- shell syntax

head2 "Shell syntax"

while IFS= read -r file; do
    if bash -n "$file" 2>/dev/null; then
        pass "$file"
    else
        fail "$file"
        bash -n "$file" 2>&1 | sed 's/^/        /'
    fi
done < <(find deploy web ssh-real -name '*.sh' -type f 2>/dev/null | sort)

# ---------------------------------------------------------------------- compose

head2 "Compose configuration"

if have docker; then
    if out=$(docker compose config 2>&1 >/dev/null); then
        pass "docker compose config (default profile)"
    else
        fail "docker compose config"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi

    if out=$(docker compose --profile elastic config 2>&1 >/dev/null); then
        pass "docker compose config (elastic profile)"
    else
        fail "docker compose config --profile elastic"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi

    # Every service should resolve to an image or a buildable context.
    if svc=$(docker compose --profile elastic config --services 2>/dev/null); then
        count=$(printf '%s\n' "$svc" | grep -c . || true)
        pass "$count services defined"
    fi

    # The web container mounts ./web, not ./shared, so the one file both halves
    # read is bind-mounted on its own. Lose that line and nothing breaks
    # loudly: sb_rickroll() just falls back to the 302 for every client,
    # including the scanners that ignore redirects and are the reason the text
    # payload exists. Checked here because the logs will never tell you.
    # Matched on the target alone, and in both spellings. `docker compose config`
    # normalises volumes into long form -- source and target land on separate
    # lines -- so any pattern joining the two with a colon matches nothing and
    # reports a missing mount that is demonstrably present.
    if docker compose config 2>/dev/null \
        | grep -qE 'target: /rickroll\.txt$|:/rickroll\.txt:'; then
        pass "rickroll.txt mounted into web"
    else
        fail "shared/rickroll.txt is not mounted into the web container; \
banned clients that ignore redirects get nothing"
    fi
else
    warn "docker not found; compose not validated"
fi

if [ -f shared/rickroll.txt ]; then
    pass "shared/rickroll.txt present"
else
    fail "shared/rickroll.txt missing; every tier falls back to the redirect"
fi

# --------------------------------------------------------------- configuration

head2 "Configuration"

if [ -f .env ]; then
    pass ".env present"

    # shellcheck disable=SC1091
    set -a; . ./.env 2>/dev/null || true; set +a

    if [ "${DOMAIN:-}" = "" ] || [ "${DOMAIN:-}" = "example.com" ]; then
        warn "DOMAIN is unset or still example.com"
    else
        pass "DOMAIN=${DOMAIN}"
    fi

    if [ "${WEBSHELL_ACTION:-}" = "" ]; then
        warn "WEBSHELL_ACTION not set; the default is published in this repo -- change it"
    else
        pass "WEBSHELL_ACTION overridden"
    fi

    # Only required if you intend to run the search stack.
    if [ "${ELASTIC_PASSWORD:-}" = "" ] || [ "${KIBANA_PASSWORD:-}" = "" ]; then
        warn "ELASTIC_PASSWORD / KIBANA_PASSWORD empty (fine unless using --profile elastic)"
    else
        pass "Elastic credentials set"
        if [ "${ELASTIC_PASSWORD}" = "${KIBANA_PASSWORD}" ]; then
            fail "ELASTIC_PASSWORD and KIBANA_PASSWORD are identical; use different values"
        fi
    fi
else
    warn ".env not present (cp .env.example .env)"
fi

if [ -f persona/persona.json ]; then
    pass "persona generated (this deployment has its own fingerprint)"
else
    warn "no persona: running the PUBLISHED defaults from this repo."
    warn "  Anyone with the source can fingerprint this host in a few lines."
    warn "  ./deploy/generate-persona.sh"
fi

if [ -f certs/origin.pem ] && [ -f certs/origin.key ]; then
    pass "TLS origin material present"
    perms=$(stat -c '%a' certs/origin.key 2>/dev/null || echo "?")
    if [ "$perms" != "600" ] && [ "$perms" != "?" ]; then
        fail "certs/origin.key is mode ${perms}; must be 600"
    fi
else
    warn "certs/origin.pem or origin.key missing; the web container self-signs as a fallback"
fi

# ------------------------------------------------------------------- git safety

head2 "Git safety"

if [ -d .git ]; then
    leaked=0
    for path in .env certs storage admin-dashboard/config admin-dashboard/admin-logs \
                intial.md IMPLEMENTATION_SUMMARY.md docker-compose.override.yml; do
        [ -e "$path" ] || continue
        if git check-ignore -q "$path" 2>/dev/null; then
            pass "ignored: $path"
        else
            fail "NOT ignored and present: $path"
            leaked=1
        fi
    done
    [ "$leaked" -eq 0 ] && pass "no sensitive path is trackable"

    if git ls-files --error-unmatch .env >/dev/null 2>&1; then
        fail ".env is already tracked in git history -- rotate every secret in it"
    fi
else
    warn "not a git repository yet (git init -b main)"
fi

# ------------------------------------------------------------------ host limits

head2 "Host limits"

if [ -r /proc/sys/vm/max_map_count ]; then
    mmc=$(cat /proc/sys/vm/max_map_count)
    if [ "$mmc" -ge 262144 ]; then
        pass "vm.max_map_count=${mmc}"
    else
        warn "vm.max_map_count=${mmc}; Elasticsearch needs >=262144 (run bootstrap.sh)"
    fi

    total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    total_mb=$((total_kb / 1024))
    if [ "$total_mb" -ge 7500 ]; then
        pass "RAM ${total_mb}MB (full stack incl. Elasticsearch)"
    elif [ "$total_mb" -ge 3500 ]; then
        warn "RAM ${total_mb}MB: fine without --profile elastic, tight with it"
    elif [ "$total_mb" -gt 0 ]; then
        fail "RAM ${total_mb}MB is below the 2GB floor"
    fi
else
    warn "not Linux; host limits not checked (they apply on the VPS, not here)"
fi

# ----------------------------------------------------------------------- result

printf '\n'
if [ "$FAILED" -gt 0 ]; then
    printf '\033[31m%d check(s) failed\033[0m, %d warning(s)\n' "$FAILED" "$WARNED"
    exit 1
fi
printf '\033[32mAll checks passed\033[0m, %d warning(s)\n' "$WARNED"
exit 0
