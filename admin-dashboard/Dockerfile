FROM python:3.11-slim

RUN groupadd -g 1000 admin \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin admin

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root app.py setup.py geoip.py ./
COPY --chown=root:root templates/ ./templates/
COPY --chown=root:root static/ ./static/

# config/ holds admin-config.json (bind-mounted); admin-logs/ holds the audit trail.
RUN mkdir -p /app/config /app/admin-logs \
 && chown -R admin:admin /app/config /app/admin-logs

# Remove every setuid/setgid binary inherited from the base image. Combined with
# no-new-privileges and cap_drop:ALL this leaves no local privilege-escalation
# path even if the dashboard itself were compromised.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER admin

ENV PYTHONUNBUFFERED=1 \
    ADMIN_CONFIG=/app/config/admin-config.json \
    AUDIT_LOG=/app/admin-logs/audit.jsonl

EXPOSE 8443

# Binds 0.0.0.0 inside the container. docker-compose publishes it to 127.0.0.1
# on the host only, so it is reachable solely through an SSH tunnel.
#
# --threads > 1 selects the gthread worker, which keeps notifying the arbiter
# from its accept loop while a request is still running -- so a bulk evidence
# export streaming for several minutes does not look like a hung worker. The
# raised timeout is belt and braces for that: this is a loopback-only operator
# service, so a generous ceiling costs nothing and a killed export halfway
# through a multi-gigabyte download costs the operator the whole download.
CMD ["gunicorn", "--bind", "0.0.0.0:8443", "--workers", "2", "--threads", "4", \
     "--timeout", "900", "--graceful-timeout", "30", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "app:app"]
