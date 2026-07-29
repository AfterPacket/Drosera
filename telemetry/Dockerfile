FROM python:3.11-slim

RUN groupadd -g 1000 telemetry \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin telemetry

WORKDIR /app

# Stdlib only, deliberately. The reporter is the one honeypot-side component
# that opens an outbound connection, and the collector is internet-facing on the
# project host; neither should carry a dependency tree that needs watching.
COPY --chown=root:root aggregate.py reporter.py collector.py ./

RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER telemetry

ENV PYTHONUNBUFFERED=1 \
    STORAGE_DIR=/var/honeypot/storage

# The reporter by default -- that is the honeypot-side role. The collector runs
# on the project host and overrides this (see telemetry/README.md).
CMD ["python3", "reporter.py"]
