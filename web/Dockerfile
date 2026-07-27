FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# nginx-full (not -light) guarantees the realip module is present, which the
# Cloudflare CF-Connecting-IP handling depends on.
# fileinfo and json are built into php8.1-common; there are no separate packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx-full \
      php8.1-fpm php8.1-redis php8.1-mbstring php8.1-curl \
      openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -M -s /usr/sbin/nologin honeypot

# Our pool replaces the stock www pool entirely.
COPY php-fpm.conf /etc/php/8.1/fpm/pool.d/honeypot.conf
RUN rm -f /etc/php/8.1/fpm/pool.d/www.conf

# The stock GLOBAL config (not the pool) logs to /var/log/php8.1-fpm.log. With a
# read-only rootfs that path is unwritable, and FPM aborts during config
# post-processing before it ever serves a request -- which presents as the whole
# container restart-looping. Log to stderr instead, which is where the rest of
# this stack's output goes anyway.
RUN sed -i -e 's#^error_log = .*#error_log = /proc/self/fd/2#' \
           -e 's#^;*daemonize = .*#daemonize = no#' \
    /etc/php/8.1/fpm/php-fpm.conf

COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/*.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Everything nginx and php-fpm touch at runtime must be writable by UID 1000,
# since neither process ever runs as root here.
RUN mkdir -p /tmp/nginx /var/honeypot/storage /var/lib/nginx /var/log/nginx \
             /etc/nginx/certs /run/php \
 && chown -R honeypot:honeypot /tmp/nginx /var/honeypot/storage /var/lib/nginx \
                               /var/log/nginx /run/php \
 && chmod 0750 /var/honeypot/storage

# Ubuntu ships su, mount, umount, chsh, chfn, gpasswd, newgrp and passwd setuid.
# This is the internet-facing container, so strip them all. Combined with
# no-new-privileges and cap_drop:ALL there is no local escalation path left.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

# Unprivileged ports; the host publishes 80/443 onto these.
EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS -o /dev/null http://127.0.0.1:8080/ || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
