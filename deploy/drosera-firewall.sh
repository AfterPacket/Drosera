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

# Kibana's access network. It is not internal -- it cannot be, because Docker
# installs no DNAT for a published port on an internal network and Kibana
# publishes 127.0.0.1:5601 -- so like the honeypot subnet it is blocked here
# instead. It was previously left to Docker's default pool, which put it
# outside the one rule that mattered: the container rendering attacker strings
# into a browser was the only one in the appliance that could reach the
# internet, and nothing said so.
KIBANA_SUBNET="${KIBANA_SUBNET:-172.30.0.0/16}"

# Everything denied egress. Space-separated; add to it rather than adding
# another near-identical block below.
BLOCKED="${BLOCKED_SUBNETS:-$HP_SUBNET $KIBANA_SUBNET}"

command -v iptables >/dev/null 2>&1 || { echo "iptables not found" >&2; exit 0; }

# DOCKER-USER is created by Docker. If the daemon has not finished starting,
# make the chain ourselves rather than failing -- Docker will adopt it.
iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER 2>/dev/null

# Remove any previous copies first, so re-running cannot stack duplicates and
# cannot leave the order wrong. Order is the whole point: the RETURNs have to
# sit above the DROP.
for net in $BLOCKED; do
    while iptables -C DOCKER-USER -s "$net" -j DROP 2>/dev/null; do
        iptables -D DOCKER-USER -s "$net" -j DROP
    done
    while iptables -C DOCKER-USER -s "$net" -d "$net" -j RETURN 2>/dev/null; do
        iptables -D DOCKER-USER -s "$net" -d "$net" -j RETURN
    done
    # Cross-subnet RETURNs from an earlier revision of this script, which
    # allowed the honeypot subnet to reach Kibana. Removed explicitly rather
    # than left to the loop above, because a host that ran that version keeps
    # the rule until something deletes it by name.
    for peer in $BLOCKED; do
        [ "$net" = "$peer" ] && continue
        while iptables -C DOCKER-USER -s "$net" -d "$peer" -j RETURN 2>/dev/null; do
            iptables -D DOCKER-USER -s "$net" -d "$peer" -j RETURN
        done
    done
done
while iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
done

# Inserted at position 1 in reverse order, so they end up as:
#   1. established/related  -> RETURN   (replies to inbound connections)
#   2. net -> same net      -> RETURN   (our own services talking to Redis)
#   3. net -> anywhere      -> DROP     (no egress)
#
# Same subnet only. A blocked subnet reaching a *different* blocked subnet is
# not something any of these containers needs: the honeypots talk to Redis on
# their own network, and Kibana reaches Elasticsearch over elastic-internal,
# which sources from 172.28 and never matches these rules at all. Allowing the
# cross product would hand a compromised honeypot a route to Kibana, which is
# the opposite of why Kibana was put behind a rule in the first place.
for net in $BLOCKED; do
    iptables -I DOCKER-USER 1 -s "$net" -j DROP
done
for net in $BLOCKED; do
    iptables -I DOCKER-USER 1 -s "$net" -d "$net" -j RETURN
done
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

echo "drosera-firewall: egress denied for ${BLOCKED}"
