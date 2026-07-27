#!/usr/bin/env bash
#
# Download and install the MaxMind GeoLite2-City database.
#
# The database cannot ship with this repo -- it is licensed, and redistribution
# is not permitted -- so it is fetched with your own credentials. MaxMind
# refreshes it weekly; run this from cron to keep geolocation from drifting as
# address blocks are reassigned.
#
#   ./deploy/update-geoip.sh
#
# Credentials come from .env (or the environment):
#   MAXMIND_ACCOUNT_ID=1234567
#   MAXMIND_LICENSE_KEY=xxxxxxxxxxxxxxxx
#
# Create the key at maxmind.com -> My Account -> Manage License Keys.
#
# Weekly, via cron:
#   0 4 * * 1 root /opt/drosera/deploy/update-geoip.sh >> /var/log/drosera-geoip.log 2>&1

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1

TARGET_DIR="${REPO_DIR}/elastic/geoip"
TARGET="${TARGET_DIR}/GeoLite2-City.mmdb"
URL="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }

if [ -f .env ]; then
    # shellcheck disable=SC1091
    set -a; . ./.env 2>/dev/null || true; set +a
fi

ACCOUNT="${MAXMIND_ACCOUNT_ID:-}"
KEY="${MAXMIND_LICENSE_KEY:-}"

if [ -z "$ACCOUNT" ] || [ -z "$KEY" ]; then
    cat >&2 <<'EOF'
MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY are required.

  1. Sign up free:  https://www.maxmind.com/en/geolite2/signup
  2. My Account -> Manage License Keys -> Generate new key
  3. Add both to .env:

       MAXMIND_ACCOUNT_ID=1234567
       MAXMIND_LICENSE_KEY=xxxxxxxxxxxxxxxx
EOF
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "downloading GeoLite2-City"
if ! curl -fsSL --retry 3 --retry-delay 5 -u "${ACCOUNT}:${KEY}" \
        "$URL" -o "${WORK}/geolite.tar.gz"; then
    # 401 here is almost always the Account ID being confused with the key.
    log "download failed -- check the account ID and license key"
    exit 1
fi

if ! tar -xzf "${WORK}/geolite.tar.gz" -C "$WORK"; then
    log "archive could not be extracted"
    exit 1
fi

FOUND="$(find "$WORK" -name 'GeoLite2-City.mmdb' -print -quit)"
if [ -z "$FOUND" ]; then
    log "no GeoLite2-City.mmdb inside the archive"
    exit 1
fi

mkdir -p "$TARGET_DIR"
# Install to a temp name and rename: readers mmap this file, so replacing it
# in place could hand a container a half-written database.
install -m 0644 "$FOUND" "${TARGET}.new"
mv -f "${TARGET}.new" "$TARGET"
log "installed $(du -h "$TARGET" | cut -f1) to ${TARGET}"

# Readers hold the file open, so they need a restart to pick up the new one.
if command -v docker >/dev/null; then
    docker compose restart admin-dashboard >/dev/null 2>&1 \
        && log "admin-dashboard restarted"
    if docker ps --format '{{.Names}}' | grep -q '^hp-elastic-shipper$'; then
        docker compose --profile elastic restart elastic-shipper >/dev/null 2>&1 \
            && log "elastic-shipper restarted"
    fi
fi

log "done"
