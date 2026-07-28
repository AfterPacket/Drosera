FROM python:3.11-slim

# No third-party packages: urllib is enough for one HTTPS API, and this is the
# only container in the deployment with outbound network access. Every
# dependency here would be a dependency reachable from the internet.

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin honeypot

WORKDIR /app
COPY vt.py /app/vt.py

USER honeypot
ENTRYPOINT ["python3", "-u", "/app/vt.py"]
