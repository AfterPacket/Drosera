#!/bin/bash
# One-shot host preparation for a dedicated Drosera VPS.
#
# Creates the storage layout with the right ownership, configures ufw, installs
# the fail2ban jail, logrotate policy, and the disk watchdog. Safe to re-run.
#
#   sudo ADMIN_IP=203.0.113.10 ./deploy/bootstrap.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UID_HP=1000
GID_HP=1000

info()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m!!\033[0m %s\n' "$*"; }
die()   { printf '\033[0;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"

# ------------------------------------------------------------------ pre-flight

command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

if [[ ! -f "${REPO_DIR}/.env" ]]; then
    info "Creating .env from .env.example"
    cp "${REPO_DIR}/.env.example" "${REPO_DIR}/.env"
    warn "Edit ${REPO_DIR}/.env and set DOMAIN before starting."
fi

# ------------------------------------------------------------- storage layout

info "Creating storage layout"
install -d -o "$UID_HP" -g "$GID_HP" -m 0750 \
    "${REPO_DIR}/storage" \
    "${REPO_DIR}/storage/logs" \
    "${REPO_DIR}/storage/sessions" \
    "${REPO_DIR}/storage/clips" \
    "${REPO_DIR}/storage/evidence" \
    "${REPO_DIR}/storage/upload-tmp"

# Read-only mount into elastic-shipper; present so the bind mount does not get
# created root-owned by Docker on first start.
install -d -m 0755 "${REPO_DIR}/elastic/geoip"

install -d -o "$UID_HP" -g "$GID_HP" -m 0700 \
    "${REPO_DIR}/admin-dashboard/config" \
    "${REPO_DIR}/admin-dashboard/admin-logs"

install -d -m 0755 "${REPO_DIR}/certs"
touch "${REPO_DIR}/storage/evidence/fail2ban.log"
chown "$UID_HP:$GID_HP" "${REPO_DIR}/storage/evidence/fail2ban.log"

# ------------------------------------------------------------------- firewall

if command -v ufw >/dev/null; then
    info "Configuring ufw"
    ADMIN_IP="${ADMIN_IP:-}"

    ufw --force default deny incoming >/dev/null
    ufw --force default allow outgoing >/dev/null

    # Every honeypot port. Any connection to these is an alert by definition.
    for port in 21 22 23 25 80 139 443 445 3306 3389; do
        ufw allow "${port}/tcp" >/dev/null
    done
    # FTP passive data range.
    ufw allow 30000:30019/tcp >/dev/null

    if [[ -n "$ADMIN_IP" ]]; then
        ufw allow from "$ADMIN_IP" to any port 2222 proto tcp >/dev/null
        info "Real SSH (2222) restricted to ${ADMIN_IP}"
    else
        warn "ADMIN_IP not set: port 2222 was NOT opened."
        warn "Run ssh-real/cutover.sh before letting the honeypot take port 22."
    fi

    ufw --force enable >/dev/null
    info "ufw active"
else
    warn "ufw not installed; skipping firewall configuration"
fi

# ------------------------------------------------------------------- fail2ban

if command -v fail2ban-server >/dev/null; then
    info "Installing fail2ban filter, action, and jail"
    install -m 0644 "${REPO_DIR}/fail2ban/honeypot-filter.conf" \
        /etc/fail2ban/filter.d/honeypot.conf
    install -m 0644 "${REPO_DIR}/fail2ban/action.d/ufw-honeypot.conf" \
        /etc/fail2ban/action.d/ufw-honeypot.conf

    # Point the jail at this checkout's evidence log.
    sed "s#^logpath *=.*#logpath = ${REPO_DIR}/storage/evidence/fail2ban.log#" \
        "${REPO_DIR}/fail2ban/honeypot-jail.conf" \
        > /etc/fail2ban/jail.d/honeypot.conf
    chmod 0644 /etc/fail2ban/jail.d/honeypot.conf

    systemctl restart fail2ban || warn "fail2ban restart failed; check its logs"
    info "fail2ban jail installed"
else
    warn "fail2ban not installed. Install it to enforce bans at the firewall:"
    warn "  apt-get install -y fail2ban && sudo $0"
fi

# ------------------------------------------------------------------ logrotate

info "Installing logrotate policy"
sed "s#__REPO__#${REPO_DIR}#g" "${REPO_DIR}/deploy/logrotate-drosera" \
    > /etc/logrotate.d/drosera
chmod 0644 /etc/logrotate.d/drosera

# ------------------------------------------------------------------- watchdog

info "Installing disk/health watchdog (every 10 minutes)"
install -m 0755 "${REPO_DIR}/deploy/watchdog.sh" /usr/local/bin/drosera-watchdog
cat > /etc/cron.d/drosera-watchdog <<EOF
# Drosera fail-safe: prune storage and restart unhealthy containers.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/10 * * * * root DROSERA_DIR=${REPO_DIR} /usr/local/bin/drosera-watchdog >> /var/log/drosera-watchdog.log 2>&1
EOF
chmod 0644 /etc/cron.d/drosera-watchdog

# ------------------------------------------------------- docker daemon policy

# Applied before the stack is started. Re-running this bounces the daemon, so it
# only rewrites daemon.json when the content would actually change.
DAEMON_JSON=/etc/docker/daemon.json
DESIRED_DAEMON=$(cat <<'EOF'
{
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Soft": 4096, "Hard": 8192 }
  }
}
EOF
)

if [[ ! -f "$DAEMON_JSON" ]] || ! diff -q <(echo "$DESIRED_DAEMON") "$DAEMON_JSON" >/dev/null 2>&1; then
    info "Applying Docker daemon hardening to ${DAEMON_JSON}"
    [[ -f "$DAEMON_JSON" ]] && cp -a "$DAEMON_JSON" "${DAEMON_JSON}.bak.$(date +%s)"
    mkdir -p /etc/docker
    echo "$DESIRED_DAEMON" > "$DAEMON_JSON"
    if systemctl is-active --quiet docker; then
        warn "Restarting Docker to apply daemon policy (containers will bounce)"
        systemctl restart docker || warn "docker restart failed; check 'journalctl -u docker'"
    fi
else
    info "Docker daemon policy already current"
fi

# userns-remap is the strongest remaining container-escape mitigation: root
# inside a container maps to an unprivileged host UID. It is NOT enabled here
# because it remaps bind-mount ownership, which would break ./storage and
# ./admin-dashboard/config until they are re-chowned to the mapped range.
# See "Optional: user namespace remapping" in deploy/README.md.

# --------------------------------------------------- noexec on captured data

# storage/ holds attacker-supplied bytes. Nothing there is ever executed, but a
# noexec bind mount makes that structural rather than a matter of trust.
if ! findmnt -no OPTIONS "${REPO_DIR}/storage" 2>/dev/null | grep -q noexec; then
    if ! grep -q "${REPO_DIR}/storage" /etc/fstab 2>/dev/null; then
        info "Adding noexec,nosuid,nodev bind mount for storage/"
        printf '%s %s none bind,noexec,nosuid,nodev 0 0\n' \
            "${REPO_DIR}/storage" "${REPO_DIR}/storage" >> /etc/fstab
        mount --bind "${REPO_DIR}/storage" "${REPO_DIR}/storage" 2>/dev/null || true
        mount -o remount,bind,noexec,nosuid,nodev "${REPO_DIR}/storage" 2>/dev/null \
            || warn "could not remount storage noexec (harmless; data is never executed)"
    fi
else
    info "storage/ already mounted noexec"
fi

# ------------------------------------------------------- honeypot egress block

# The honeypot bridge cannot be `internal: true` -- Docker will not publish
# ports on an internal network, which would leave every honeypot unreachable.
# So the containers sit on a normal bridge and egress is denied here instead.
#
# DOCKER-USER is consulted before Docker's own FORWARD rules and survives
# daemon restarts, which is why the rules go here rather than in FORWARD.
info "Blocking honeypot egress via DOCKER-USER"

HP_SUBNET="172.25.0.0/16"

# Idempotent: drop any rules we previously added before re-adding them.
while iptables -C DOCKER-USER -s "$HP_SUBNET" -j DROP 2>/dev/null; do
    iptables -D DOCKER-USER -s "$HP_SUBNET" -j DROP
done
while iptables -C DOCKER-USER -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN
done
while iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
done

# Inserted in reverse order, so the final chain reads:
#   1. ESTABLISHED,RELATED -> RETURN   (replies to attackers we accepted)
#   2. subnet -> subnet    -> RETURN   (honeypots reaching redis)
#   3. subnet -> anywhere  -> DROP     (no phoning home, no pivoting)
iptables -I DOCKER-USER 1 -s "$HP_SUBNET" -j DROP
iptables -I DOCKER-USER 1 -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save >/dev/null 2>&1 \
        || warn "could not persist iptables rules; re-run this script after reboot"
else
    warn "iptables-persistent not installed: egress rules are lost on reboot."
    warn "  apt-get install -y iptables-persistent   (then re-run this script)"
fi

# --------------------------------------------------------------- kernel limits

info "Raising connection tracking limits for tarpit workloads"
cat > /etc/sysctl.d/99-drosera.conf <<'EOF'
# Tarpits hold many connections open for a long time.
net.netfilter.nf_conntrack_max = 262144
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 4096
# Required by Docker to route between the bridge networks and the host. This is
# not general routing: the containers that must not reach the internet are held
# on `internal: true` networks, which Docker enforces with firewall rules rather
# than by disabling forwarding.
net.ipv4.ip_forward = 1
# Redirects and source routing stay off regardless -- nothing here should ever
# be steerable into forwarding traffic on someone else's behalf.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
# Elasticsearch refuses to start below this. Set persistently so the search
# stack survives a host reboot.
vm.max_map_count = 262144
EOF
sysctl -p /etc/sysctl.d/99-drosera.conf >/dev/null 2>&1 || \
    warn "some sysctl values could not be applied (normal on some VPS kernels)"

# ---------------------------------------------------------------------- done

cat <<EOF

  Host preparation complete.

  Next:
    1. Edit ${REPO_DIR}/.env and set DOMAIN.
    2. Install the Cloudflare Origin Certificate:
         ${REPO_DIR}/certs/origin.pem
         ${REPO_DIR}/certs/origin.key   (chmod 600)
    3. Move real SSH off port 22:
         sudo ADMIN_IP=<your ip> ${REPO_DIR}/ssh-real/cutover.sh
    4. Create the dashboard admin account:
         docker compose run --rm admin-dashboard python3 setup.py
    5. Start everything:
         docker compose up -d --build

  Full walkthrough: ${REPO_DIR}/deploy/README.md

EOF
