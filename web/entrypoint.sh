#!/bin/bash
# Prepare writable scratch space, resolve TLS material, then run php-fpm and
# nginx side by side. Runs as UID 1000 -- nothing here needs root.
#
# bash, not sh: `wait -n` is a bashism and Ubuntu's /bin/sh is dash.
set -euo pipefail

NGINX_TMP=/tmp/nginx
CERT_DIR=/etc/nginx/certs
SSL_CONF="${NGINX_TMP}/ssl.conf"

mkdir -p "${NGINX_TMP}/client_body" "${NGINX_TMP}/proxy" "${NGINX_TMP}/fastcgi" \
         "${NGINX_TMP}/uwsgi" "${NGINX_TMP}/scgi"
# /run is a tmpfs at runtime, which replaces whatever the image had there, so
# php-fpm's directory has to be recreated on every start.
mkdir -p /run/php
mkdir -p /var/honeypot/storage/logs /var/honeypot/storage/sessions \
         /var/honeypot/storage/evidence /var/honeypot/storage/upload-tmp

# Prefer the Cloudflare Origin Certificate. Fall back to a self-signed pair so
# the container still starts (Cloudflare "Full" trusts it; "Full (Strict)" does
# not, which is exactly the signal that the real cert is missing).
if [[ -s "${CERT_DIR}/origin.pem" && -s "${CERT_DIR}/origin.key" ]]; then
    echo "[entrypoint] using Cloudflare origin certificate"
    printf 'ssl_certificate %s/origin.pem;\nssl_certificate_key %s/origin.key;\n' \
        "${CERT_DIR}" "${CERT_DIR}" > "${SSL_CONF}"
else
    echo "[entrypoint] WARNING: no origin certificate at ${CERT_DIR}/origin.pem"
    echo "[entrypoint] generating a self-signed fallback -- keep Cloudflare SSL mode"
    echo "[entrypoint] on Full (not Strict) until you install the real one."
    mkdir -p "${NGINX_TMP}/selfsigned"
    if [[ ! -s "${NGINX_TMP}/selfsigned/origin.pem" ]]; then
        openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "${NGINX_TMP}/selfsigned/origin.key" \
            -out "${NGINX_TMP}/selfsigned/origin.pem" \
            -subj "/CN=${SERVER_NAME:-localhost}" >/dev/null 2>&1
    fi
    printf 'ssl_certificate %s/selfsigned/origin.pem;\nssl_certificate_key %s/selfsigned/origin.key;\n' \
        "${NGINX_TMP}" "${NGINX_TMP}" > "${SSL_CONF}"
fi

php-fpm8.1 --nodaemonize --fpm-config /etc/php/8.1/fpm/php-fpm.conf &
FPM_PID=$!

# Wait for the FastCGI listener (127.0.0.1:9000 -> hex 2328) before nginx starts.
for _ in $(seq 1 60); do
    if grep -qi ':2328 ' /proc/net/tcp 2>/dev/null; then
        break
    fi
    if ! kill -0 "${FPM_PID}" 2>/dev/null; then
        echo "[entrypoint] php-fpm exited during startup" >&2
        exit 1
    fi
    sleep 0.2
done

nginx -g 'daemon off;' &
NGINX_PID=$!

shutdown() {
    kill -TERM "${FPM_PID}" "${NGINX_PID}" 2>/dev/null || true
}
trap shutdown TERM INT

# If either process dies, exit non-zero so Docker's restart policy recycles us.
wait -n "${FPM_PID}" "${NGINX_PID}"
echo "[entrypoint] a child process exited; shutting down" >&2
shutdown
wait || true
exit 1
