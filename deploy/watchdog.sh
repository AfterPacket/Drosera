#!/bin/bash
# Drosera fail-safe watchdog. Runs from cron every 10 minutes.
#
# A honeypot under sustained attack generates data fast. This keeps the box
# alive without supervision:
#   - prunes old evidence before the disk fills
#   - hard-stops writes if the disk is critically low
#   - restarts containers that have gone unhealthy or died
#   - restarts the stack if Redis has become unreachable
#
# Everything it does is local and reversible. It never deletes anything newer
# than RETENTION_DAYS unless the disk is genuinely about to fill.

set -uo pipefail

DROSERA_DIR="${DROSERA_DIR:-/opt/drosera}"
STORAGE="${DROSERA_DIR}/storage"

RETENTION_DAYS="${RETENTION_DAYS:-90}"
DISK_WARN_PCT="${DISK_WARN_PCT:-80}"
DISK_CRIT_PCT="${DISK_CRIT_PCT:-92}"
EMERGENCY_RETENTION_DAYS="${EMERGENCY_RETENTION_DAYS:-7}"

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }

cd "$DROSERA_DIR" 2>/dev/null || { log "FATAL: ${DROSERA_DIR} not found"; exit 1; }

# ------------------------------------------------------------------ disk usage

usage_pct=$(df --output=pcent "$STORAGE" 2>/dev/null | tail -1 | tr -dc '0-9')
usage_pct=${usage_pct:-0}

if (( usage_pct >= DISK_WARN_PCT )); then
    log "WARN: disk at ${usage_pct}% -- pruning data older than ${RETENTION_DAYS}d"
    find "${STORAGE}/logs"     -name '*.jsonl' -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null
    find "${STORAGE}/sessions" -name '*.cast'  -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null
    find "${STORAGE}/upload-tmp" -type f -mmin +60 -delete 2>/dev/null
fi

usage_pct=$(df --output=pcent "$STORAGE" 2>/dev/null | tail -1 | tr -dc '0-9')
usage_pct=${usage_pct:-0}

if (( usage_pct >= DISK_CRIT_PCT )); then
    log "CRITICAL: disk at ${usage_pct}% -- emergency prune to ${EMERGENCY_RETENTION_DAYS}d"
    find "${STORAGE}/sessions" -name '*.cast'  -mtime "+${EMERGENCY_RETENTION_DAYS}" -delete 2>/dev/null
    find "${STORAGE}/logs"     -name '*.jsonl' -mtime "+${EMERGENCY_RETENTION_DAYS}" -delete 2>/dev/null

    # Session recordings are the bulkiest and least evidentially unique data,
    # so shed the largest ones first rather than losing the event log.
    still=$(df --output=pcent "$STORAGE" 2>/dev/null | tail -1 | tr -dc '0-9')
    if (( ${still:-0} >= DISK_CRIT_PCT )); then
        log "CRITICAL: still at ${still}% -- dropping largest recordings"
        find "${STORAGE}/sessions" -name '*.cast' -printf '%s %p\n' 2>/dev/null \
            | sort -rn | head -50 | cut -d' ' -f2- | xargs -r rm -f
    fi
fi

# ------------------------------------------------------- container supervision

if ! docker compose ps --quiet >/dev/null 2>&1; then
    log "ERROR: docker compose is not responding in ${DROSERA_DIR}"
    exit 1
fi

while read -r name; do
    [[ -z "$name" ]] && continue
    state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo unknown)
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
             "$name" 2>/dev/null || echo none)

    if [[ "$state" == "exited" || "$state" == "dead" ]]; then
        log "Restarting ${name} (state=${state})"
        docker start "$name" >/dev/null 2>&1 || log "  restart failed"
    elif [[ "$health" == "unhealthy" ]]; then
        log "Restarting ${name} (health=unhealthy)"
        docker restart "$name" >/dev/null 2>&1 || log "  restart failed"
    fi
done < <(docker ps -a --filter 'name=hp-' --format '{{.Names}}')

# ------------------------------------------------------------- redis liveness

if ! docker exec hp-redis-honeypot redis-cli PING >/dev/null 2>&1; then
    log "ERROR: redis-honeypot not answering PING -- restarting it"
    docker restart hp-redis-honeypot >/dev/null 2>&1
fi

# ------------------------------------------------------------ evidence backlog

# fail2ban reads this file; if it grows without bound, rotation has stopped.
evidence="${STORAGE}/evidence/fail2ban.log"
if [[ -f "$evidence" ]]; then
    size=$(stat -c %s "$evidence" 2>/dev/null || echo 0)
    if (( size > 268435456 )); then
        log "WARN: fail2ban.log is $((size / 1048576))MB -- forcing rotation"
        logrotate -f /etc/logrotate.d/drosera 2>/dev/null || true
    fi
fi

exit 0
