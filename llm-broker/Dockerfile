FROM python:3.11-slim

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

# ca-certificates only, and only for the cloud providers. With
# HONEYPOT_LLM_PROVIDER=ollama nothing here opens a TLS connection at all.
#
# There is no requirements.txt on purpose. broker.py speaks HTTP and JSON with
# the standard library, and every provider it supports is a JSON POST -- so the
# one container in this stack with both internet access and attacker-derived
# input in memory has no third-party Python in it to audit or to update.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=root:root broker.py ./

RUN mkdir -p /var/honeypot/storage \
 && chown -R honeypot:honeypot /var/honeypot/storage

# Strip every setuid/setgid binary inherited from the base image, as session-cam
# does, and for the same reason: this container can reach the internet.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

ENV PYTHONUNBUFFERED=1 \
    STORAGE_DIR=/var/honeypot/storage

CMD ["python3", "broker.py"]
