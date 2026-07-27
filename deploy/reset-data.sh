#!/usr/bin/env bash
#
# Wipe all captured data and start collecting from zero.
#
# For use while tuning: after changing the scoring table, or after your own
# testing has polluted the numbers. It clears identities, scores, bans, event
# logs, recordings and clips, and lifts the firewall bans those produced.
#
# It deliberately does NOT touch:
#   .env                             your configuration
#   certs/                           TLS material
#   admin-dashboard/config/          dashboard credentials and TOTP secret
#   admin-dashboard/admin-logs/      the operator audit trail
#
# THIS DESTROYS EVIDENCE. Anything captured so far is gone, including data you
# might want for an abuse report. Export first if that matters:
#   Dashboard -> the IP -> Export evidence (ZIP)
#
#   ./deploy/reset-data.sh --yes

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1

if [[ "${1:-}" != "--yes" ]]; then
    cat <<EOF

  This will permanently delete:

    - every per-IP identity, score and ban in redis-honeypot
    - storage/logs/*.jsonl          (the event log)
    - storage/sessions/*            (recordings and their sidecars)
    - storage/clips/*               (rendered video)
    - storage/evidence/fail2ban.log (the ban trail)
    - all active fail2ban and ufw bans this honeypot created

  Dashboard credentials, .env, certs and the audit log are left alone.

  Re-run with --yes to proceed.

EOF
    exit 1
fi

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "Stopping the stack"
docker compose down 2>/dev/null || true

step "Flushing honeypot state from Redis"
# redis-honeypot only. redis-admin holds live dashboard sessions and is left
# alone, so this does not log the operator out.
docker compose up -d redis-honeypot >/dev/null 2>&1
for _ in $(seq 1 20); do
    docker exec hp-redis-honeypot redis-cli PING >/dev/null 2>&1 && break
    sleep 1
done
if docker exec hp-redis-honeypot redis-cli FLUSHALL >/dev/null 2>&1; then
    echo "  redis-honeypot flushed"
else
    echo "  WARNING: could not reach redis-honeypot; state may persist"
fi

step "Clearing captured data"
rm -f  storage/logs/*.jsonl storage/logs/*.jsonl.* 2>/dev/null
rm -f  storage/sessions/*.cast storage/sessions/*.meta.json \
       storage/sessions/*.cam.json storage/sessions/*.tmp 2>/dev/null
rm -f  storage/clips/* 2>/dev/null
rm -f  storage/upload-tmp/* 2>/dev/null
rm -f  storage/.elastic-shipper.json 2>/dev/null
: > storage/evidence/fail2ban.log 2>/dev/null || true
echo "  logs, sessions, clips and the ban trail are empty"

step "Lifting firewall bans"
if command -v fail2ban-client >/dev/null; then
    # fail2ban's unban runs our ufw action, which removes the deny rule too.
    sudo fail2ban-client unban --all >/dev/null 2>&1 \
        || sudo fail2ban-client set honeypot unban --all >/dev/null 2>&1 \
        || echo "  could not unban via fail2ban; check 'ufw status numbered'"
    echo "  fail2ban bans lifted"
else
    echo "  fail2ban not installed; skipped"
fi

# Any ufw rule our action left behind is tagged with the project name.
if command -v ufw >/dev/null; then
    leftover=$(sudo ufw status numbered 2>/dev/null | grep -c 'drosera' || true)
    if [[ "${leftover:-0}" -gt 0 ]]; then
        echo "  ${leftover} ufw rule(s) still tagged 'drosera':"
        echo "    sudo ufw status numbered | grep drosera"
        echo "    sudo ufw delete <number>    # highest number first"
    fi
fi

step "Restarting"
docker compose up -d
sleep 3
docker compose ps --format '  {{.Name}}\t{{.Status}}'

printf '\n\033[32mReset complete.\033[0m Collecting from zero.\n\n'
