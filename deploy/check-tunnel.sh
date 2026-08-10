#!/usr/bin/env bash
#
# Audit the path an operator uses to reach the dashboard, from both ends.
#
# The admin dashboard and Kibana are published to 127.0.0.1 only and reached
# over `ssh -L`. That is a good design, and it moves the exposure rather than
# removing it: what protects the dashboard is now the SSH server's forwarding
# policy, and the default policy is far more permissive than this deployment
# needs.
#
# The specific thing worth understanding: with AllowTcpForwarding on and no
# PermitOpen, ANY account that can log in over SSH can forward to ANY address
# and port the VPS can reach -- every 127.0.0.1 service, every container IP,
# and every host on the VPS's network. The dashboard binding to loopback stops
# the internet reaching it. It does nothing about the tunnel itself, because
# the tunnel is the thing that was supposed to cross that boundary.
#
# REPORTS ONLY. It changes nothing -- editing sshd_config over the SSH session
# it governs is how people lock themselves out of a VPS at two in the morning.
# The recommended block is printed at the end for you to apply deliberately,
# with a second session open.
#
#     ./deploy/check-tunnel.sh

set -uo pipefail

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
DASH_PORT="${DASH_PORT:-8443}"
KIBANA_PORT="${KIBANA_PORT:-5601}"

PASS=0; WARN=0; FAIL=0

pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; WARN=$((WARN+1)); }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
head2() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Effective value of a directive, asking sshd itself rather than grepping --
# Include directives, Match blocks and later-wins ordering all make the file a
# poor source of truth. Falls back to grep only if sshd -T is unavailable.
sshd_value() {
    local key="${1,,}"
    if command -v sshd >/dev/null 2>&1 && sshd -T >/dev/null 2>&1; then
        sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}'
    else
        grep -Ei "^[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG" 2>/dev/null \
            | tail -1 | awk '{$1=""; sub(/^ /,""); print}'
    fi
}

head2 "Published ports (VPS end)"

# The dashboard must not be listening on anything but loopback. If it is, the
# tunnel is decoration.
if command -v ss >/dev/null 2>&1; then
    for port in "$DASH_PORT" "$KIBANA_PORT"; do
        listeners=$(ss -ltnH "sport = :$port" 2>/dev/null | awk '{print $4}')
        [ -z "$listeners" ] && continue
        external=$(printf '%s\n' "$listeners" | grep -vE '^(127\.0\.0\.1|\[::1\])' || true)
        if [ -n "$external" ]; then
            fail "port $port is listening beyond loopback: $(echo "$external" | tr '\n' ' ')"
        else
            pass "port $port is loopback-only"
        fi
    done
else
    warn "ss not available; could not check listeners"
fi

head2 "SSH forwarding policy (VPS end)"

# The highest-value control here by some distance. Without it, an authorised
# session can tunnel to anything the VPS can route to -- redis, elasticsearch,
# the docker API if it is ever exposed, and every other host on the subnet.
permit_open=$(sshd_value permitopen)
case "$permit_open" in
    ""|any)
        fail "PermitOpen is unset: any SSH session may forward to any host and port"
        ;;
    *"$DASH_PORT"*)
        pass "PermitOpen restricts forwarding to: $permit_open"
        ;;
    *)
        warn "PermitOpen is set but does not mention $DASH_PORT: $permit_open"
        ;;
esac

# If the VPS is ever compromised, agent forwarding hands the attacker the use
# of the operator's private keys against every other host those keys open. It
# is the single worst default to leave on for a box whose entire job is to be
# attacked.
agent=$(sshd_value allowagentforwarding)
if [ "$agent" = "no" ]; then
    pass "AllowAgentForwarding no"
else
    fail "AllowAgentForwarding is '${agent:-yes (default)}' -- a compromised VPS could use your keys elsewhere"
fi

gateway=$(sshd_value gatewayports)
if [ "$gateway" = "no" ]; then
    pass "GatewayPorts no"
else
    fail "GatewayPorts is '$gateway' -- forwarded ports would be exposed beyond loopback"
fi

tunnel=$(sshd_value permittunnel)
if [ "$tunnel" = "no" ]; then
    pass "PermitTunnel no"
else
    warn "PermitTunnel is '${tunnel:-no (default)}'"
fi

streamlocal=$(sshd_value allowstreamlocalforwarding)
if [ "$streamlocal" = "no" ]; then
    pass "AllowStreamLocalForwarding no"
else
    warn "AllowStreamLocalForwarding is '${streamlocal:-yes (default)}' -- unix socket forwarding is available"
fi

x11=$(sshd_value x11forwarding)
if [ "$x11" = "no" ]; then
    pass "X11Forwarding no"
else
    warn "X11Forwarding is '$x11'"
fi

head2 "SSH authentication (VPS end)"

passwd_auth=$(sshd_value passwordauthentication)
if [ "$passwd_auth" = "no" ]; then
    pass "PasswordAuthentication no"
else
    fail "PasswordAuthentication is '$passwd_auth' -- this box advertises itself as a target"
fi

root_login=$(sshd_value permitrootlogin)
case "$root_login" in
    no|prohibit-password|forced-commands-only) pass "PermitRootLogin $root_login" ;;
    *) fail "PermitRootLogin is '$root_login'" ;;
esac

# Port 22 belongs to the honeypot. If real sshd is also there, the two are
# fighting over it and one of them is not doing its job.
ssh_port=$(sshd_value port)
if [ "$ssh_port" = "22" ]; then
    fail "sshd is on port 22, which the telnet/ssh honeypot expects to own"
else
    pass "sshd is on port ${ssh_port:-unknown}, not 22"
fi

head2 "Container egress (VPS end)"

if command -v iptables >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    rules=$(iptables -S DOCKER-USER 2>/dev/null)
    for subnet in 172.25.0.0/16 172.30.0.0/16; do
        if printf '%s' "$rules" | grep -q -- "-s $subnet.*-j DROP"; then
            pass "egress denied for $subnet"
        else
            fail "no DROP rule for $subnet -- run deploy/drosera-firewall.sh"
        fi
    done
else
    warn "not root, or iptables unavailable; skipped DOCKER-USER inspection"
fi

head2 "Summary"
printf '  %d ok, %d warning(s), %d failure(s)\n' "$PASS" "$WARN" "$FAIL"

if [ "$FAIL" -gt 0 ] || [ "$WARN" -gt 0 ]; then
cat <<'RECOMMENDED'

  ── Recommended sshd_config, applied deliberately ─────────────────────
  Nothing above has been changed. Open a SECOND session before editing
  this file, and keep it open until you have confirmed the new config
  works -- `sshd -t` validates syntax, not that you can still log in.

    # Reachable services are the dashboard and Kibana, and nothing else.
    # Without this line an authorised session can forward to any address
    # the VPS can route to.
    PermitOpen 127.0.0.1:8443 127.0.0.1:5601

    AllowTcpForwarding yes          # required: this is how -L works
    AllowAgentForwarding no         # a compromised VPS must not borrow your keys
    AllowStreamLocalForwarding no
    GatewayPorts no
    PermitTunnel no
    X11Forwarding no

    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitRootLogin no

  Then:  sshd -t && systemctl reload ssh

  ── Client end ────────────────────────────────────────────────────────
  In ~/.ssh/config on the machine you browse from:

    Host drosera
        HostName <vps>
        Port <sshd port>
        User <you>
        # Explicitly loopback: without the bind address, a client with
        # GatewayPorts set would put the dashboard on your LAN.
        LocalForward 127.0.0.1:8443 127.0.0.1:8443
        LocalForward 127.0.0.1:5601 127.0.0.1:5601
        ForwardAgent no
        ExitOnForwardFailure yes
        RequestTTY no

  Then:  ssh -N drosera
RECOMMENDED
fi

[ "$FAIL" -gt 0 ] && exit 1
exit 0
