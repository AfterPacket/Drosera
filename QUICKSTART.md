# Quick Start

The condensed path. For anything that surprises you, use
[`deploy/README.md`](deploy/README.md), which explains why each step exists.

**Before you begin:** fill in the attestation in
[`AUTHORIZATION.md`](AUTHORIZATION.md) and confirm your hosting provider allows
honeypot operation. Use a VPS dedicated entirely to this — nothing else on it.

---

## 1. Host prep (5 min)

```bash
curl -fsSL https://get.docker.com | sh
apt-get install -y ufw fail2ban logrotate git

git clone <your-repo> /opt/drosera && cd /opt/drosera
sudo ADMIN_IP=$(curl -s ifconfig.me) ./deploy/bootstrap.sh
```

`ADMIN_IP` is the address *you* connect from. It is the one address that stays
allowed on the real SSH port.

## 2. Configure (2 min)

```bash
nano .env       # set DOMAIN; the rest have working defaults
```

## 3. Cloudflare (5 min)

- DNS → `A` record → your VPS IP → **Proxied** (orange cloud)
- SSL/TLS → **Full** for now (switch to Full (Strict) after step 4)
- Edge Certificates → Always Use HTTPS **on**, Min TLS **1.2**
- Speed → Rocket Loader **off** (it rewrites the deliberate WordPress tells)
- Security → Bot Fight Mode **on**; WAF rules set to **Log**, not Block
- Caching → **Standard** (never "Cache Everything" — it would cache tarpits)

## 4. Origin certificate (3 min)

Cloudflare → SSL/TLS → **Origin Server** → Create Certificate. Then:

```bash
sudo nano /opt/drosera/certs/origin.pem     # paste certificate
sudo nano /opt/drosera/certs/origin.key     # paste private key
sudo chmod 600 /opt/drosera/certs/origin.key
```

Now switch Cloudflare to **Full (Strict)**.

Skipping this still works — the container generates a self-signed cert — but you
must leave Cloudflare on **Full**, not Strict.

## 5. Admin account (3 min)

```bash
docker compose build admin-dashboard
docker compose run --rm admin-dashboard python3 setup.py
```

Scan the QR code. **Save the base32 secret in your password manager** — there
are no backup codes.

## 6. Move real SSH off port 22 (5 min)

```bash
sudo ADMIN_IP=$(curl -s ifconfig.me) ./ssh-real/cutover.sh
```

Then, **from a new terminal** (leave the current one open):

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 you@your-vps
sudo /opt/drosera/ssh-real/cutover.sh --confirm
```

If you cannot get in, do nothing — SSH restores itself to port 22 after 90
seconds.

Once confirmed, delete the leftover `Port 22` line from `/etc/ssh/sshd_config`
and restart sshd so the honeypot can bind it.

## 7. Launch (2 min)

```bash
docker compose up -d --build
docker compose ps
```

## 8. Verify

Containment — this **must** fail:

```bash
docker compose exec ssh-honey python3 -c \
  "import socket; socket.create_connection(('1.1.1.1',53),timeout=5)"
```

The site is up:

```bash
curl -sI https://your-domain.com/ | head -3
```

## 9. Dashboard

```bash
ssh -N -L 8443:127.0.0.1:8443 -p 2222 you@your-vps
```

Open <http://127.0.0.1:8443/> → password → TOTP.

## 10. Test from somewhere else

**Never test from your admin IP.** Use a VPN exit or a second VPS.

```bash
curl -sI https://your-domain.com/.env
ssh root@your-domain.com                      # any password is accepted
curl -v --max-time 30 https://your-domain.com/backup.sql   # should hang, dripping
```

Then clear the test IP:

```bash
TEST_IP=203.0.113.99
MD5=$(printf '%s' "$TEST_IP" | md5sum | cut -d' ' -f1)
docker exec hp-redis-honeypot redis-cli DEL "hp:identity:$MD5" "hp:banned:$MD5"
sudo fail2ban-client set honeypot unbanip $TEST_IP 2>/dev/null
```

## 11. Monitor the monitor

Nothing pages you when a honeypot dies. Point UptimeRobot / Healthchecks.io at
`https://your-domain.com/` on a 5-minute check.

---

## Daily use

```bash
tail -f storage/logs/$(date -u +%F).jsonl     # live events
docker compose logs -f web                    # service logs
tail -f /var/log/drosera-watchdog.log        # fail-safe activity
sudo fail2ban-client status honeypot          # enforced bans
df -h /opt/drosera                           # disk headroom
```

## Common problems

| Symptom | Fix |
|---|---|
| nginx will not start | `docker compose logs web` — config errors are explicit |
| Dashboard login loops | Set `ADMIN_COOKIE_SECURE=false` for tunnel access |
| TOTP rejected | Clock drift: `timedatectl set-ntp true` |
| Port 22 in use | Remove the leftover `Port 22` from `sshd_config` |
| Tarpit 404s instantly | `TARPIT_MAX_CONCURRENT` reached — by design |
| Bans not enforced | `fail2ban-client status honeypot`; check `logpath` |
