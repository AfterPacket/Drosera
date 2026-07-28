FROM python:3.11-slim

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

# fonts-dejavu-core: the renderer needs a real monospace face. Pillow's builtin
# bitmap font is a fallback, but it renders terminal output badly.
# ca-certificates: required for TLS to api.telegram.org and any SMTP relay.
# ffmpeg: what makes full-session playback deliverable. Every frame of a long
# session as a GIF runs to tens of megabytes and is dropped at CAM_MAX_CLIP_MB;
# the same frames as H.264 arrive comfortably inside Telegram's limit. Without
# it the renderer falls back to a sampled GIF, so this is the difference between
# watching the session and watching an excerpt. From Debian's archive, pinned by
# the base image's snapshot, not a binary fetched from anywhere else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      fonts-dejavu-core ca-certificates ffmpeg \
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
