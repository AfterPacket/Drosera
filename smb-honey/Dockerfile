FROM python:3.11-slim

RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

RUN pip install --no-cache-dir redis==5.0.1

COPY --chown=root:root fake_smbd.py .

RUN mkdir -p /var/honeypot/storage && chown -R honeypot:honeypot /var/honeypot/storage

# Remove every setuid/setgid binary inherited from the base image. Combined with
# no-new-privileges and cap_drop:ALL this leaves no local privilege-escalation
# path even if the service itself were compromised.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

ENV PYTHONUNBUFFERED=1 LISTEN_PORT_SMB=4445 LISTEN_PORT_NBT=4139
EXPOSE 4445 4139

CMD ["python3", "fake_smbd.py"]
