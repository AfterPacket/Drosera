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

# City gives coordinates for the map; ASN gives the network the address belongs
# to, which is the more actionable of the two -- attacks cluster by hosting
# provider far harder than by country, and a provider has an abuse desk where a
# country does not. MaxMind ship them as separate editions under one licence.
EDITIONS="GeoLite2-City GeoLite2-ASN"

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
mkdir -p "$TARGET_DIR"

INSTALLED=0
for EDITION in $EDITIONS; do
    ARCHIVE="${WORK}/${EDITION}.tar.gz"
    URL="https://download.maxmind.com/geoip/databases/${EDITION}/download?suffix=tar.gz"

    log "downloading ${EDITION}"
    if ! curl -fsSL --retry 3 --retry-delay 5 -u "${ACCOUNT}:${KEY}" \
            "$URL" -o "$ARCHIVE"; then
        # 401 here is almost always the Account ID being confused with the key.
        log "${EDITION}: download failed -- check the account ID and license key"
        continue
    fi

    if ! tar -xzf "$ARCHIVE" -C "$WORK"; then
        log "${EDITION}: archive could not be extracted"
        continue
    fi

    FOUND="$(find "$WORK" -name "${EDITION}.mmdb" -print -quit)"
    if [ -z "$FOUND" ]; then
        log "${EDITION}: no ${EDITION}.mmdb inside the archive"
        continue
    fi

    TARGET="${TARGET_DIR}/${EDITION}.mmdb"
    # Install to a temp name and rename: readers mmap this file, so replacing
    # it in place could hand a container a half-written database.
    install -m 0644 "$FOUND" "${TARGET}.new"
    mv -f "${TARGET}.new" "$TARGET"
    log "installed $(du -h "$TARGET" | cut -f1) to ${TARGET}"
    INSTALLED=$((INSTALLED + 1))
done

# One edition failing should not discard the other -- a deployment with City
# and no ASN still maps attacks, and saying so beats exiting on the first
# problem and leaving the operator to guess which half worked.
if [ "$INSTALLED" -eq 0 ]; then
    log "nothing installed"
    exit 1
fi

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
