#!/bin/bash
# Move real administrative SSH off port 22 so the honeypot can claim it.
#
# Safety model: a deadman switch, not a self-test. Verifying connectivity from
# the box itself proves nothing -- loopback bypasses the firewall entirely, so a
# rule that locks you out still "passes". Instead this schedules an unconditional
# rollback and requires you to cancel it from a genuinely new session on the new
# port. If you cannot get back in, you do nothing and the box repairs itself.
#
#   1. sudo ADMIN_IP=203.0.113.10 ./cutover.sh
#   2. from a NEW terminal:  ssh -p 2222 you@vps
#   3. in that session:      sudo ./cutover.sh --confirm
#
# Never run step 3 from the original session. That defeats the whole point.

set -euo pipefail

OLD_PORT="${OLD_PORT:-22}"
NEW_PORT="${NEW_PORT:-2222}"
ROLLBACK_SECONDS="${ROLLBACK_SECONDS:-90}"

SSHD_CONFIG=/etc/ssh/sshd_config
STATE_DIR=/run/ssh-cutover
BACKUP="${STATE_DIR}/sshd_config.backup"
PIDFILE="${STATE_DIR}/rollback.pid"
REPORT=/root/ssh-cutover-report.txt

log() { printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$REPORT"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

# ---------------------------------------------------------------- confirm mode

if [[ "${1:-}" == "--confirm" ]]; then
    [[ -f "$PIDFILE" ]] || die "no cutover is pending (nothing to confirm)"

    # Refuse to confirm from the session that would be rolled back anyway.
    #
    # sudo resets the environment, so SSH_CONNECTION is absent here even when we
    # are on an SSH session -- which used to make this check pass without
    # checking anything, defeating the whole point of the deadman switch. Walk up
    # to the owning sshd and read it out of that process instead.
    conn="${SSH_CONNECTION:-}"
    if [[ -z "$conn" ]]; then
        pid=$PPID
        while [[ "$pid" -gt 1 ]]; do
            if [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == "sshd" ]]; then
                conn=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null \
                       | sed -n 's/^SSH_CONNECTION=//p' | head -1)
                [[ -n "$conn" ]] && break
            fi
            pid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null) || break
            [[ -n "$pid" ]] || break
        done
    fi

    peer_port=""
    [[ -n "$conn" ]] && peer_port=$(awk '{print $4}' <<<"$conn")

    if [[ -z "$peer_port" ]]; then
        die "cannot determine which port this session is on.
  Confirming blind would defeat the deadman switch, so this is a hard stop.
  Re-run preserving the environment:   sudo -E $0 --confirm"
    fi
    if [[ "$peer_port" != "$NEW_PORT" ]]; then
        die "you are connected on port ${peer_port}, not ${NEW_PORT}. Open a new session on ${NEW_PORT} first."
    fi

    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    log "CONFIRMED on port ${NEW_PORT} from ${conn%% *}. Rollback cancelled."
    log "RESULT: SUCCESS -- real SSH is now on ${NEW_PORT}, port ${OLD_PORT} is free for the honeypot."
    echo
    echo "  Cutover complete. Remaining steps:"
    echo "    1. Confirm the honeypot has port ${OLD_PORT}:  ss -tlnp | grep ':${OLD_PORT}'"
    echo "    2. Report written to ${REPORT}"
    exit 0
fi

if [[ "${1:-}" == "--rollback" ]]; then
    log "Manual rollback requested."
    [[ -f "$BACKUP" ]] && cp -a "$BACKUP" "$SSHD_CONFIG"
    ufw allow "${OLD_PORT}/tcp" >/dev/null 2>&1 || true
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
    rm -f "$PIDFILE"
    log "RESULT: MANUAL ROLLBACK COMPLETE -- SSH is back on ${OLD_PORT}."
    exit 0
fi

# ------------------------------------------------------------------ pre-flight

ADMIN_IP="${ADMIN_IP:-}"
[[ -n "$ADMIN_IP" ]] || die "ADMIN_IP is required.
  Set it to the address you administer from:
      sudo ADMIN_IP=203.0.113.10 $0
  Find it with:  curl -s ifconfig.me
  Use 'any' only if you have a dynamic address and accept the exposure:
      sudo ADMIN_IP=any $0"

if [[ "$ADMIN_IP" != "any" ]]; then
    grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9a-fA-F:]+(/[0-9]{1,3})?$' \
        <<<"$ADMIN_IP" || die "ADMIN_IP '${ADMIN_IP}' is not a valid IP or CIDR"
fi

[[ -f "$SSHD_CONFIG" ]] || die "$SSHD_CONFIG not found"
command -v ufw >/dev/null || die "ufw is not installed"
[[ -f "$PIDFILE" ]] && die "a cutover is already pending. Run '$0 --confirm' or '$0 --rollback'."

# Key-based auth is the only thing that makes this survivable.
if ! ls /root/.ssh/authorized_keys "${HOME}/.ssh/authorized_keys" >/dev/null 2>&1; then
    die "no authorized_keys found. Set up key auth before moving the SSH port."
fi

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

{
    echo
    echo "=========================================="
    echo " SSH cutover  $(date -Is)"
    echo "=========================================="
} >> "$REPORT"

log "Admin source: ${ADMIN_IP}"
log "Moving sshd: ${OLD_PORT} -> ${NEW_PORT}"
log "Rollback fires in ${ROLLBACK_SECONDS}s unless confirmed."

# ------------------------------------------------------------------- apply

cp -a "$SSHD_CONFIG" "$BACKUP"
log "Backed up ${SSHD_CONFIG} -> ${BACKUP}"
ufw status numbered > "${STATE_DIR}/ufw-before.txt" 2>&1 || true

# Listen on BOTH ports during the window: if the new port is unreachable the old
# session stays alive, which is what makes the rollback recoverable.
if grep -Eq "^[[:space:]]*Port[[:space:]]+" "$SSHD_CONFIG"; then
    sed -i -E "s/^[[:space:]]*Port[[:space:]]+.*/Port ${NEW_PORT}\nPort ${OLD_PORT}/" "$SSHD_CONFIG"
else
    printf '\nPort %s\nPort %s\n' "$NEW_PORT" "$OLD_PORT" >> "$SSHD_CONFIG"
fi
log "sshd_config now listens on ${NEW_PORT} and ${OLD_PORT}"

if ! sshd -t 2>>"$REPORT"; then
    cp -a "$BACKUP" "$SSHD_CONFIG"
    die "sshd config test failed; original restored. See ${REPORT}."
fi

if [[ "$ADMIN_IP" == "any" ]]; then
    ufw allow "${NEW_PORT}/tcp" >/dev/null
    log "ufw: allow ${NEW_PORT}/tcp from anywhere"
else
    ufw allow from "$ADMIN_IP" to any port "$NEW_PORT" proto tcp >/dev/null
    log "ufw: allow ${NEW_PORT}/tcp from ${ADMIN_IP}"
fi

systemctl restart ssh 2>/dev/null || systemctl restart sshd
log "sshd restarted"

# --------------------------------------------------------- schedule rollback

# setsid + nohup so the timer outlives this shell and the SSH session that
# started it. If your connection dies, the rollback still fires.
setsid nohup bash -c "
    sleep ${ROLLBACK_SECONDS}
    if [[ -f '${PIDFILE}' ]]; then
        cp -a '${BACKUP}' '${SSHD_CONFIG}'
        ufw allow ${OLD_PORT}/tcp >/dev/null 2>&1 || true
        systemctl restart ssh 2>/dev/null || systemctl restart sshd
        rm -f '${PIDFILE}'
        printf '[%s] AUTO-ROLLBACK fired: not confirmed within ${ROLLBACK_SECONDS}s. SSH restored to ${OLD_PORT}.\n' \
            \"\$(date -Is)\" >> '${REPORT}'
    fi
" >/dev/null 2>&1 &
echo $! > "$PIDFILE"
log "Rollback armed (pid $(cat "$PIDFILE"))"

PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")

cat <<EOF

  ==========================================================
   ACT NOW -- rollback fires in ${ROLLBACK_SECONDS} seconds
  ==========================================================

  1. Leave this session OPEN.

  2. In a NEW terminal, verify key auth works on the new port:

       ssh -p ${NEW_PORT} -i ~/.ssh/id_ed25519 ${SUDO_USER:-$USER}@${PUBLIC_IP}

  3. In that NEW session, cancel the rollback:

       sudo ${BASH_SOURCE[0]} --confirm

  If step 2 fails, do nothing. SSH returns to port ${OLD_PORT} automatically.
  To roll back immediately:  sudo ${BASH_SOURCE[0]} --rollback

  Report: ${REPORT}

EOF
