FROM python:3.11-slim

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

# fonts-dejavu-core: the renderer needs a real monospace face. Pillow's builtin
# bitmap font is a fallback, but it renders terminal output badly.
# ca-certificates: required for TLS to api.telegram.org and any SMTP relay.
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-dejavu-core ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root cam.py render.py ./

RUN mkdir -p /var/honeypot/storage \
 && chown -R honeypot:honeypot /var/honeypot/storage

# Remove every setuid/setgid binary inherited from the base image. This matters
# more here than anywhere else in the stack: this is the one container that can
# reach the internet.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

ENV PYTHONUNBUFFERED=1 \
    STORAGE_DIR=/var/honeypot/storage

CMD ["python3", "cam.py"]
