#!/bin/sh
# Obtain and renew a Let's Encrypt certificate, unattended, forever.
#
# DNS-01 ONLY. The other two challenge types cannot work here:
#   - HTTP-01 needs /.well-known/acme-challenge/ to be served, but the honeypot
#     answers every unknown path with fake scanner bait, and the web container
#     has a read-only rootfs so there is nowhere to drop a token anyway.
#   - TLS-ALPN-01 cannot pass through the Cloudflare proxy.
#
# DNS-01 needs no inbound anything, which also means this works before the
# domain resolves to the box and keeps working if you change providers.
#
# Publishes to /certs/origin.{pem,key} -- the same paths the Cloudflare Origin
# Certificate would use, so the web container needs no special knowledge of
# where a certificate came from. It watches those files and reloads nginx.
set -eu

DOMAIN="${DOMAIN:?DOMAIN is required}"
EMAIL="${LETSENCRYPT_EMAIL:?LETSENCRYPT_EMAIL is required}"
TOKEN="${CF_DNS_API_TOKEN:?CF_DNS_API_TOKEN is required}"
STAGING="${LETSENCRYPT_STAGING:-false}"
INTERVAL="${LETSENCRYPT_CHECK_INTERVAL:-43200}"   # twice a day
PROPAGATION="${LETSENCRYPT_PROPAGATION_SECONDS:-30}"

CREDS=/tmp/cloudflare.ini
LIVE="/etc/letsencrypt/live/${DOMAIN}"

log() { echo "[certbot] $*"; }

# Written at runtime from the environment rather than mounted: one less secret
# file to manage, and it lives on a tmpfs that never touches disk.
umask 077
printf 'dns_cloudflare_api_token = %s\n' "$TOKEN" > "$CREDS"

STAGING_FLAG=""
if [ "$STAGING" = "true" ]; then
    # Let's Encrypt rate-limits hard: 5 failures per hostname per hour, and 50
    # certificates per domain per week. Get the plumbing right against staging
    # before you burn real quota.
    STAGING_FLAG="--staging"
    log "using the STAGING environment -- these certificates are not trusted"
fi

publish() {
    [ -s "${LIVE}/fullchain.pem" ] || return 1
    # 1000:1000 is the web container's user, which opens the key directly.
    # install(1) sets owner and mode atomically, so the key is never briefly
    # world-readable on the shared volume.
    install -o 1000 -g 1000 -m 0644 "${LIVE}/fullchain.pem" /certs/origin.pem
    install -o 1000 -g 1000 -m 0600 "${LIVE}/privkey.pem"   /certs/origin.key
    log "published certificate for ${DOMAIN} to /certs"
}

obtain() {
    certbot certonly \
        --non-interactive --agree-tos --keep-until-expiring \
        --email "$EMAIL" \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CREDS" \
        --dns-cloudflare-propagation-seconds "$PROPAGATION" \
        --cert-name "$DOMAIN" \
        -d "$DOMAIN" -d "*.${DOMAIN}" \
        $STAGING_FLAG
}

log "starting for ${DOMAIN} (checking every ${INTERVAL}s)"

while true; do
    if obtain; then
        publish || log "certbot succeeded but no certificate was found at ${LIVE}"
    else
        # Never exit on failure. A DNS hiccup or a rate limit should mean "try
        # again later", not a container that restart-loops and hammers the ACME
        # API until the account is blocked.
        log "renewal attempt failed; retrying in ${INTERVAL}s"
    fi
    sleep "$INTERVAL"
done
