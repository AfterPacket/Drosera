#!/bin/bash
# Remove nftables rules that name a bridge which no longer exists.
#
# Docker >=28 writes rules into the `raw` PREROUTING chain so a published port
# cannot be bypassed by addressing the container directly:
#
#   ip daddr 172.25.0.2 iifname != "br-4964bdc7466b" drop
#
# They are meant to be removed with the network. When a network is destroyed
# while the daemon is restarting they leak, and the bridge they name stops
# existing -- at which point the rule drops EVERY packet to that address,
# because none of them can have arrived on an interface that is gone.
#
# Symptoms, all of which point away from the actual cause:
#
#   - containers cannot reach each other; connections time out
#   - `iptables -L` shows nothing dropped anywhere, because `raw` PREROUTING
#     runs before conntrack and before FORWARD
#   - ARP works fine, so the bridge looks healthy
#   - the HOST can reach the container, because host-originated traffic goes
#     through OUTPUT rather than PREROUTING
#   - adding ACCEPT rules to DOCKER-USER changes nothing
#
# Safe to run at any time: it only deletes rules whose interface is missing.
# Docker rewrites the correct ones when containers start.

set -uo pipefail

if ! command -v nft >/dev/null 2>&1; then
    echo "nft not installed; nothing to do" >&2
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

stale_bridges=""
for br in $(nft list chain ip raw PREROUTING 2>/dev/null \
            | grep -o 'br-[0-9a-f]\{12\}' | sort -u); do
    ip link show "$br" >/dev/null 2>&1 || stale_bridges="${stale_bridges} ${br}"
done

if [ -z "$stale_bridges" ]; then
    echo "No stale rules found."
    exit 0
fi

echo "Stale bridge(s):${stale_bridges}"

removed=0
for br in $stale_bridges; do
    # Handles are re-numbered as rules are deleted, so re-read the chain for
    # each one rather than collecting them all up front.
    while :; do
        handle=$(nft -a list chain ip raw PREROUTING 2>/dev/null \
                 | grep "$br" | grep -o 'handle [0-9]*' | head -1 | awk '{print $2}')
        [ -z "$handle" ] && break
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "  would delete handle $handle ($br)"
            break
        fi
        nft delete rule ip raw PREROUTING handle "$handle" 2>/dev/null || break
        removed=$((removed + 1))
    done
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run; nothing changed."
else
    echo "Removed ${removed} rule(s)."
    echo "Verify with: ./deploy/smoke-test.sh"
fi
