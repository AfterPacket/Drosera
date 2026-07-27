#!/usr/bin/env bash
#
# Fetch the world landmass outline used by the attack map.
#
# Natural Earth 110m land, public domain (CC0), roughly 100 KB. Unlike the
# GeoIP database this may be redistributed freely, so once fetched you can
# commit it and nobody else needs to run this.
#
# Downloaded on the host, never in a container: the dashboard has no egress and
# is not going to get any.
#
#   ./deploy/update-worldmap.sh

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${REPO_DIR}/admin-dashboard/static/world.geojson"

# Natural Earth's own repository. 110m is the coarsest tier, which is the right
# one here -- at dashboard size, finer coastlines cost bandwidth and render
# time to draw detail nobody can see.
URL="https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_land.geojson"

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "downloading Natural Earth 110m land"
if ! curl -fsSL --retry 3 --retry-delay 3 "$URL" -o "${WORK}/world.geojson"; then
    log "download failed"
    exit 1
fi

# Cheap sanity check before overwriting anything: a captive portal or an error
# page would otherwise be installed as the map and fail silently in the browser.
if ! grep -q '"FeatureCollection"' "${WORK}/world.geojson"; then
    log "downloaded file is not GeoJSON"
    exit 1
fi

install -m 0644 "${WORK}/world.geojson" "$TARGET"
log "installed $(du -h "$TARGET" | cut -f1) to ${TARGET}"

if command -v docker >/dev/null; then
    (cd "$REPO_DIR" && docker compose up -d --build admin-dashboard >/dev/null 2>&1) \
        && log "admin-dashboard rebuilt"
fi

log "done -- this file is public domain and can be committed"
