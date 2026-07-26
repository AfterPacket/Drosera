#!/usr/bin/env bash
#
# certbot deploy hook: publish a renewed Let's Encrypt pair to the web container.
#
# Optional. The Cloudflare Origin Certificate is the recommended path -- it is
# valid for 15 years and needs no renewal machinery at all, and the origin cert
# is only ever presented to Cloudflare, so public trust buys nothing. Use this
# if you are running grey-cloud (unproxied) and therefore need a publicly
# trusted certificate.
#
# ONLY DNS-01 WORKS HERE:
#   - HTTP-01 fails because /.well-known/acme-challenge/ is swallowed by the
#     honeypot's catch-all scanner trap, and the web container's read-only
#     rootfs gives certbot nowhere to write a webroot.
#   - TLS-ALPN-01 cannot pass through the Cloudflare proxy.
#
# Issue with:
#
#   apt-get install -y certbot python3-certbot-dns-cloudflare
#   install -d -m 0700 /root/.secrets
#   printf 'dns_cloudflare_api_token = %s\n' "<Zone:DNS:Edit token>" \
#       > /root/.secrets/cloudflare.ini
#   chmod 600 /root/.secrets/cloudflare.ini
#
#   DROSERA_DOMAIN=example.com certbot certonly \
#       --dns-cloudflare \
#       --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
#       -d example.com -d '*.example.com' \
#       --deploy-hook /opt/drosera/deploy/letsencrypt-hook.sh
#
# certbot's systemd timer runs renewals thereafter and invokes this on success.
# Put DROSERA_DOMAIN in /etc/default/drosera or edit the default below, because
# the timer will not inherit it from your shell.

set -euo pipefail

DOMAIN="${DROSERA_DOMAIN:-example.com}"
REPO_DIR="${DROSERA_DIR:-/opt/drosera}"
LIVE="/etc/letsencrypt/live/${DOMAIN}"

if [[ ! -s "${LIVE}/fullchain.pem" || ! -s "${LIVE}/privkey.pem" ]]; then
    echo "[letsencrypt-hook] no certificate at ${LIVE}" >&2
    exit 1
fi

# Ownership is the part that catches people out. The web container runs as UID
# 1000 and nginx opens the key itself, so a root-owned 0600 key is unreadable --
# and the failure is quiet, because the entrypoint's `-s` test only stats the
# file. It reports "using Cloudflare origin certificate", then nginx dies with
# a permission error and the container restart-loops. install(1) sets owner and
# mode atomically, which also avoids exposing a world-readable key mid-copy.
install -o 1000 -g 1000 -m 0644 "${LIVE}/fullchain.pem" "${REPO_DIR}/certs/origin.pem"
install -o 1000 -g 1000 -m 0600 "${LIVE}/privkey.pem"   "${REPO_DIR}/certs/origin.key"

echo "[letsencrypt-hook] installed certificate for ${DOMAIN}"

# Restart rather than reload: nginx runs as PID 1's child inside the container
# and the entrypoint regenerates its ssl.conf on start, so a restart is the
# supported way to pick up new material.
docker compose -f "${REPO_DIR}/docker-compose.yml" restart web

echo "[letsencrypt-hook] web container restarted"
