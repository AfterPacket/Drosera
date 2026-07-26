FROM python:3.11-slim

# Non-root from the start. The container listens on 2222 and the host maps 22 to
# it, so no capability to bind privileged ports is ever needed.
RUN groupadd -g 1000 honeypot \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root fake_sshd.py .

RUN mkdir -p /app/state /var/honeypot/storage \
 && chown -R honeypot:honeypot /app/state /var/honeypot/storage

# Remove every setuid/setgid binary inherited from the base image. Combined with
# no-new-privileges and cap_drop:ALL this leaves no local privilege-escalation
# path even if the service itself were compromised.
RUN find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

USER honeypot

ENV PYTHONUNBUFFERED=1 LISTEN_PORT=2222
EXPOSE 2222

CMD ["python3", "fake_sshd.py"]
