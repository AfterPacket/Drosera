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
# php-fpm's directory has to be recreated on every start. Non-fatal under
# `set -e`: with --nodaemonize php-fpm writes no pid file, so a failure here
# should not take the container down.
mkdir -p /run/php 2>/dev/null || true
mkdir -p /var/honeypot/storage/logs /var/honeypot/storage/sessions \
         /var/honeypot/storage/evidence /var/honeypot/storage/upload-tmp

# Point nginx at the best certificate available right now. A function rather
# than a one-shot block because the answer changes at runtime: with the
# letsencrypt profile, certbot publishes a real certificate a minute or two
# after first boot and replaces it every 60 days. Neither should need a
# restart, so the watcher below calls this again.
#
# Returns 0 if a real certificate is in use, 1 if we fell back to self-signed.
write_ssl_conf() {
    # -r as well as -s: a key that exists but is unreadable is the classic
    # failure here (created with sudo, so root-owned 0600, while this process
    # is UID 1000). Testing only for existence would write a config that makes
    # nginx die on start with a permission error instead of falling back.
    if [[ -s "${CERT_DIR}/origin.pem" && -s "${CERT_DIR}/origin.key" \
          && -r "${CERT_DIR}/origin.key" ]]; then
        printf 'ssl_certificate %s/origin.pem;\nssl_certificate_key %s/origin.key;\n' \
            "${CERT_DIR}" "${CERT_DIR}" > "${SSL_CONF}"
        return 0
    fi

    mkdir -p "${NGINX_TMP}/selfsigned"
    if [[ ! -s "${NGINX_TMP}/selfsigned/origin.pem" ]]; then
        openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "${NGINX_TMP}/selfsigned/origin.key" \
            -out "${NGINX_TMP}/selfsigned/origin.pem" \
            -subj "/CN=${SERVER_NAME:-localhost}" >/dev/null 2>&1
    fi
    printf 'ssl_certificate %s/selfsigned/origin.pem;\nssl_certificate_key %s/selfsigned/origin.key;\n' \
        "${NGINX_TMP}" "${NGINX_TMP}" > "${SSL_CONF}"
    return 1
}

cert_stamp() { stat -c %Y "${CERT_DIR}/origin.pem" 2>/dev/null || echo none; }

if write_ssl_conf; then
    echo "[entrypoint] using certificate at ${CERT_DIR}/origin.pem"
else
    if [[ -e "${CERT_DIR}/origin.key" && ! -r "${CERT_DIR}/origin.key" ]]; then
        echo "[entrypoint] WARNING: ${CERT_DIR}/origin.key exists but is not readable"
        echo "[entrypoint] by UID 1000. Fix with: chown 1000:1000 certs/origin.*"
    else
        echo "[entrypoint] WARNING: no certificate at ${CERT_DIR}/origin.pem"
    fi
    echo "[entrypoint] using a self-signed fallback -- keep Cloudflare SSL mode on"
    echo "[entrypoint] Full, not Full (Strict), until a real certificate appears."
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

# Pick up a certificate that appears or is renewed while we are running.
#
# certbot writes into the shared certs/ volume and has no way to signal us --
# it holds no docker socket, deliberately, since handing the internet-facing
# container's neighbour control over the daemon would undo the containment
# model. So we poll the mtime. A renewal is live within a minute, and the
# 60-day cycle needs no operator involvement at all.
(
    last=$(cert_stamp)
    while sleep 60; do
        current=$(cert_stamp)
        [[ "$current" == "$last" ]] && continue
        last="$current"
        if write_ssl_conf && nginx -s reload 2>/dev/null; then
            echo "[entrypoint] certificate changed; nginx reloaded"
        fi
    done
) &

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
