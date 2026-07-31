#!/bin/bash
# Install the honeypot egress rules into DOCKER-USER. Idempotent.
#
# Run at boot by drosera-firewall.service, ordered after docker.service, rather
# than restored from a saved ruleset. That distinction matters more than it
# looks:
#
# `netfilter-persistent save` captures EVERY table, including the chains Docker
# rewrites on its own -- DOCKER, DOCKER-FORWARD, and the `raw` PREROUTING rules
# it uses to stop published ports being bypassed. Those reference bridges by
# name, and bridge names change whenever a network is recreated. So a saved
# ruleset is stale the moment anything moves, and replaying it at boot
# reinstates rules naming bridges that no longer exist.
#
# The `raw` ones are actively dangerous when stale, because they are written as
# a NEGATED interface match:
#
#   -A PREROUTING -d 172.25.0.2/32 ! -i br-<old> -j DROP
#
# Once br-<old> is gone, `! -i br-<old>` matches everything, and every packet
# to that address is dropped -- before conntrack, before FORWARD, invisible to
# `iptables -L`. See deploy/clean-stale-nft.sh.
#
# Docker rebuilds all of its own rules at startup from the live networks. It
# needs no help. The only rules that are ours are the three below.

set -uo pipefail

HP_SUBNET="${HP_SUBNET:-172.25.0.0/16}"

command -v iptables >/dev/null 2>&1 || { echo "iptables not found" >&2; exit 0; }

# DOCKER-USER is created by Docker. If the daemon has not finished starting,
# make the chain ourselves rather than failing -- Docker will adopt it.
iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER 2>/dev/null

# Remove any previous copies first, so re-running cannot stack duplicates and
# cannot leave the order wrong. Order is the whole point: the RETURNs have to
# sit above the DROP.
while iptables -C DOCKER-USER -s "$HP_SUBNET" -j DROP 2>/dev/null; do
    iptables -D DOCKER-USER -s "$HP_SUBNET" -j DROP
done
while iptables -C DOCKER-USER -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN
done
while iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
done

# Inserted at position 1 in reverse order, so they end up as:
#   1. established/related  -> RETURN   (replies to inbound connections)
#   2. honeypot -> honeypot -> RETURN   (our own services talking to Redis)
#   3. honeypot -> anywhere -> DROP     (no egress)
iptables -I DOCKER-USER 1 -s "$HP_SUBNET" -j DROP
iptables -I DOCKER-USER 1 -s "$HP_SUBNET" -d "$HP_SUBNET" -j RETURN
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

echo "drosera-firewall: egress rules installed for ${HP_SUBNET}"
