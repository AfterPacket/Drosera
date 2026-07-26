FROM python:3.11-slim

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root shipper.py .

RUN mkdir -p /var/honeypot/storage /geoip \
 && chown -R honeypot:honeypot /var/honeypot/storage

# Remove every setuid/setgid binary inherited from the base image.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

ENV PYTHONUNBUFFERED=1 \
    STORAGE_DIR=/var/honeypot/storage

CMD ["python3", "shipper.py"]
