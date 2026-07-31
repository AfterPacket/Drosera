"""Fake machine identity generator and per-IP state cache.

Redis is the single source of truth. Whichever service sees an IP first writes
the identity; every other service reads it back, so an attacker who hits the web
shell and then SSH sees one consistent fake machine. Generation is seeded from
crc32(ip) so a lost cache regenerates the same values.

Every public function degrades to an in-process fallback if Redis is unreachable
rather than raising into a protocol handler.
"""

import hashlib
import ipaddress
import json
import os
import random
import threading
import time
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis

from . import persona

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
IDENTITY_TTL = 7 * 24 * 3600
BAN_TTL = int(os.getenv("HONEYPOT_BAN_TTL", str(7 * 24 * 3600)))
MAX_HISTORY = 200

# Addresses that are never scored, tarpitted or banned.
#
# Without this the operator's own browsing is indistinguishable from an attack:
# visiting your own site a few times tarpits you to 3 KB/s, and a few more
# crosses the ban threshold and writes a ufw deny rule against your address.
# It also keeps your traffic out of the statistics, which is the other half of
# the problem -- you are not a threat actor and should not be in the data.
#
# Entries may be single addresses or CIDR ranges.
def _parse_networks(raw: str) -> list:
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks


def _default_gateway() -> str:
    """The bridge gateway address, read from the container's routing table.

    This is the host reaching in, and it is the source of every health check,
    every `deploy/smoke-test.sh` run and every curl an operator fires from the
    box itself. Scored like an attacker it climbed to 27 of the 35-point ban
    threshold in a few hours across all six services -- and the ban would have
    been the damaging part, not the score: services would start refusing the
    host, and fail2ban's action is `ufw insert 1 deny from <ip>`, which against
    a bridge gateway cuts the host off from every container it runs.

    Detected rather than configured because the subnet is Docker's to choose,
    so a hardcoded 172.x would be wrong on someone else's deployment.
    """
    try:
        with open("/proc/net/route", "r", encoding="ascii") as handle:
            next(handle)                                  # header
            for line in handle:
                fields = line.split()
                # Destination 0.0.0.0 is the default route; its gateway is
                # stored as little-endian hex.
                if len(fields) > 2 and fields[1] == "00000000" and fields[2] != "00000000":
                    return str(ipaddress.IPv4Address(
                        int(fields[2], 16).to_bytes(4, "little")))
    except (OSError, ValueError, StopIteration):
        pass
    return ""


IGNORE_NETWORKS = _parse_networks(os.getenv("HONEYPOT_IGNORE_IPS", ""))

# On by default. An operator who genuinely wants to study traffic arriving from
# the gateway -- a compromised sibling container, say -- can set this to 0.
if os.getenv("HONEYPOT_IGNORE_GATEWAY", "1").strip().lower() not in (
        "0", "false", "no", "off"):
    _gateway = _default_gateway()
    if _gateway:
        IGNORE_NETWORKS.append(ipaddress.ip_network(f"{_gateway}/32"))


def is_ignored(ip: str) -> bool:
    """True for addresses that are ours, not an attacker's."""
    if not IGNORE_NETWORKS:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in IGNORE_NETWORKS)

# Read from the deployment's persona rather than hardcoded, because these are
# exactly what an attacker compares against a published default to identify a
# honeypot. See shared/persona.py and deploy/generate-persona.sh.
HOSTNAME_POOL = persona.pool("hostname_pool")
KERNEL_POOL = persona.pool("kernel_pool")
OS_POOL = persona.pool("os_pool")
HUMAN_USERS = [tuple(entry) for entry in persona.pool("user_pool")]

_local_cache: Dict[str, Dict[str, Any]] = {}
_local_lock = threading.Lock()
_redis_client: Optional[redis.Redis] = None
_redis_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_ip(ip: str) -> str:
    """Redis key component. MD5 here is an opaque identifier, not a security control."""
    return hashlib.md5(ip.encode()).hexdigest()


# Redis holds every identity, score and ban. Losing it does not stop the
# honeypot -- connections are still answered and still logged to disk -- but it
# does stop scoring, tarpitting and banning, which is most of the point. Two
# things follow from that, and neither was true before an outage taught us:
#
#   1. It must be LOUD. A silent downgrade to "log only" looks exactly like a
#      quiet day on the dashboard. A DEGRADED event goes to the JSONL log,
#      which is on the filesystem and needs no Redis to write, so it appears in
#      the live feed and in whatever alerting is configured.
#   2. It must be FAST. The cached client keeps answering after the server has
#      gone, so every call paid the full three-second timeout before falling
#      back -- on every connection, on every service. That is slow enough to
#      change how the honeypot behaves, which is a deception failure on top of
#      an availability one. The breaker below short-circuits to the fallback
#      until it is worth trying again.
BREAKER_TRIP = int(os.getenv("REDIS_BREAKER_FAILURES", "3"))
BREAKER_COOLDOWN = int(os.getenv("REDIS_BREAKER_COOLDOWN", "30"))

_health = {"failures": 0, "open_until": 0.0, "degraded": False}
_health_lock = threading.Lock()


def _announce(event_type: str, reason: str) -> None:
    """Record a state change to the event log. Never raises."""
    try:
        from . import alerting                       # deferred: avoids a cycle
        alerting.alert_event(ip="0.0.0.0", event_type=event_type,
                             reason=reason, service="identity")
    except Exception:                                # noqa: BLE001
        pass


def _note_failure() -> None:
    global _redis_client
    with _health_lock:
        _health["failures"] += 1
        if _health["failures"] < BREAKER_TRIP:
            return
        _health["open_until"] = time.time() + BREAKER_COOLDOWN
        first = not _health["degraded"]
        _health["degraded"] = True
    # Drop the cached client so the next attempt after the cooldown reconnects
    # rather than reusing a socket to a server that is gone.
    _redis_client = None
    if first:
        _announce("IDENTITY_STORE_DEGRADED",
                  f"redis unreachable at {REDIS_HOST}:{REDIS_PORT}; "
                  "connections are still logged but NOT scored, tarpitted or banned")


def _note_success() -> None:
    with _health_lock:
        recovered = _health["degraded"]
        _health["failures"] = 0
        _health["open_until"] = 0.0
        _health["degraded"] = False
    if recovered:
        _announce("IDENTITY_STORE_RECOVERED",
                  "redis reachable again; scoring and enforcement resumed")


def degraded() -> bool:
    """True while the identity store is known to be unreachable."""
    with _health_lock:
        return _health["degraded"]


def _client() -> Optional[redis.Redis]:
    global _redis_client
    with _health_lock:
        if _health["open_until"] > time.time():
            return None                              # breaker open: fail fast
    if _redis_client is not None:
        return _redis_client
    with _redis_lock:
        if _redis_client is None:
            try:
                client = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    decode_responses=True,
                    socket_connect_timeout=3,
                    socket_timeout=3,
                    health_check_interval=30,
                    retry_on_timeout=True,
                )
                client.ping()
                _redis_client = client
            except Exception:
                _note_failure()
                return None
    _note_success()
    return _redis_client


def _generate(ip: str) -> Dict[str, Any]:
    """Deterministic from crc32(ip); uses a private Random so we never touch global state."""
    rng = random.Random(zlib.crc32(ip.encode()) & 0xFFFFFFFF)

    hostname = rng.choice(HOSTNAME_POOL)
    lan_ip = "10.0.1." + str(rng.randint(20, 240))
    wan_ip = "{}.{}.{}.{}".format(
        rng.choice([45, 51, 68, 104, 138, 159, 167, 178]),
        rng.randint(1, 254), rng.randint(1, 254), rng.randint(2, 253),
    )
    mac = "02:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))

    humans = rng.sample(HUMAN_USERS, 3)
    users: List[Dict[str, Any]] = [
        {"username": "root", "uid": 0, "gid": 0, "home": "/root",
         "shell": "/bin/bash", "groups": ["root"]},
        {"username": "www-data", "uid": 33, "gid": 33, "home": "/var/www",
         "shell": "/usr/sbin/nologin", "groups": ["www-data"]},
    ]
    for i, (name, home) in enumerate(humans):
        users.append({
            "username": name,
            "uid": 1000 + i,
            "gid": 1000 + i,
            "home": home,
            "shell": "/bin/bash",
            "groups": rng.sample(["sudo", "adm", "users", "docker", "www-data"], 2),
        })

    return {
        # Stored plainly: the Redis key is md5(ip), which is one-way, and the
        # dashboard needs the real address to render and to action bans.
        "ip": ip,
        "fake_hostname": hostname,
        "fake_kernel": rng.choice(KERNEL_POOL),
        "fake_os": rng.choice(OS_POOL),
        "fake_lan_ip": lan_ip,
        "fake_wan_ip": wan_ip,
        "fake_mac": mac,
        "fake_webroot": "/var/www/html",
        "fake_users": users,
        "fake_cwd": "/var/www/html",
        "fake_filesystem": _build_filesystem(),
        "score": 0.0,
        "tool_detected": None,
        "tarpit_active": False,
        "services_touched": [],
        "session_history": [],
        "credentials": [],
        "banned": False,
        "rickroll": False,
        "first_seen": _now(),
        "last_seen": _now(),
    }


def _build_filesystem() -> Dict[str, Any]:
    def d(**kids):
        node = {"type": "dir", "mode": "drwxr-xr-x", "children": {}}
        node["children"].update(kids)
        return node

    def f(size, mode="-rw-r--r--"):
        # Sizes are scaled by a per-deployment factor. Byte-identical `ls -la`
        # output across two hosts is as good a fingerprint as a banner, and the
        # numbers below are published in this repository.
        return {"type": "file", "mode": mode, "size": persona.jitter(size, str(size))}

    documents = persona.pool("document_pool") or ["strategic-plan-2024.pdf"]
    year, month = (persona.pool("upload_path") + ["2024", "01"])[:2]
    backup = persona.get("backup_name")

    return {
        "type": "dir",
        "mode": "drwxr-xr-x",
        "children": {
            "etc": d(**{
                "passwd": f(2114), "shadow": f(1387, "-rw-r-----"),
                "hostname": f(14), "hosts": f(221), "resolv.conf": f(78),
                "crontab": f(1042), "os-release": f(386),
                "nginx": d(**{"nginx.conf": f(1482)}),
                "mysql": d(**{"my.cnf": f(682)}),
            }),
            "var": d(**{
                "www": d(**{
                    "html": d(**{
                        "index.php": f(418), "wp-config.php": f(3214),
                        "wp-load.php": f(3843), "xmlrpc.php": f(3236),
                        ".htaccess": f(235),
                        "wp-content": d(**{
                            "uploads": d(**{
                                year: d(**{
                                    month: d(**{
                                        name: f(284918 + 9137 * index)
                                        for index, name in enumerate(documents)
                                    }),
                                }),
                            }),
                            "plugins": d(), "themes": d(),
                        }),
                        "uploads": d(),
                    }),
                }),
                "log": d(**{"syslog": f(1048576), "auth.log": f(204800)}),
                "backups": d(**{backup: f(48211904)}),
            }),
            "home": d(),
            "root": d(**{".bash_history": f(1841), ".ssh": d(**{"id_rsa": f(1679, "-rw-------")})}),
            "opt": d(**{"monitoring": d(**{"check.php": f(2140)})}),
            "tmp": d(),
        },
    }


def _fallback(ip: str) -> Dict[str, Any]:
    with _local_lock:
        if ip not in _local_cache:
            _local_cache[ip] = _generate(ip)
        return json.loads(json.dumps(_local_cache[ip]))


def get_or_create_identity(ip: str) -> Dict[str, Any]:
    """Return the cached identity for an IP, creating it on first sight."""
    # Generated but never stored. Gating only the scoring left the profile
    # itself alive: every connection still created and touched a record, so an
    # ignored address kept its page on the dashboard with last_seen ticking
    # forward and no events behind it. Callers still get a usable identity --
    # they read fake_hostname and friends out of it to answer the connection.
    if is_ignored(ip):
        return _generate(ip)

    client = _client()
    if client is None:
        return _fallback(ip)

    key = f"hp:identity:{hash_ip(ip)}"
    try:
        cached = client.get(key)
        if cached:
            _note_success()
            return json.loads(cached)
        identity = _generate(ip)
        # NX so two services racing on the same IP agree on one identity.
        if not client.set(key, json.dumps(identity), ex=IDENTITY_TTL, nx=True):
            cached = client.get(key)
            if cached:
                _note_success()
                return json.loads(cached)
        _note_success()
        return identity
    except Exception:
        # This is the call every connection makes, so it is where an outage is
        # noticed first and where the breaker is armed.
        _note_failure()
        return _fallback(ip)


def update_identity(ip: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Merge fields into the stored identity and refresh its TTL."""
    identity = get_or_create_identity(ip)
    identity.update(fields)
    identity["last_seen"] = _now()

    # Merged for the caller, never persisted. Credential capture and session
    # bookkeeping both land here, so without this an ignored address still
    # wrote a record on every connection.
    if is_ignored(ip):
        return identity

    client = _client()
    if client is None:
        with _local_lock:
            _local_cache[ip] = identity
        return identity
    try:
        client.set(f"hp:identity:{hash_ip(ip)}", json.dumps(identity), ex=IDENTITY_TTL)
    except Exception:
        with _local_lock:
            _local_cache[ip] = identity
    return identity


def touch_service(ip: str, service: str) -> Dict[str, Any]:
    """Record that an IP reached a given protocol service."""
    identity = get_or_create_identity(ip)
    touched = list(identity.get("services_touched") or [])
    if service not in touched:
        touched.append(service)
        return update_identity(ip, {"services_touched": touched})
    return update_identity(ip, {})


def score_event(ip: str, points: float, event_type: str, reason: str,
                payload: str = "", tool: str = "", service: str = "") -> Dict[str, Any]:
    """Apply points to an IP, append to history, and auto-ban past the threshold."""
    from . import alerting, scoring

    if is_ignored(ip):
        # No identity, no score, no log line. The operator is not a data point.
        return {"old_score": 0.0, "new_score": 0.0, "event": {}, "banned": False,
                "tarpitted": False, "identity": {}, "ignored": True}

    identity = get_or_create_identity(ip)
    old_score = float(identity.get("score") or 0)
    new_score = old_score + float(points)

    event = {
        "timestamp": _now(),
        "event_type": event_type,
        "points": float(points),
        "reason": reason,
        "tool": tool,
        "service": service,
        "payload": (payload or "")[:500],
    }

    history = list(identity.get("session_history") or [])
    history.append(event)

    touched = list(identity.get("services_touched") or [])
    if service and service not in touched:
        touched.append(service)

    fields: Dict[str, Any] = {
        "score": new_score,
        "session_history": history[-MAX_HISTORY:],
        "services_touched": touched,
    }
    if tool:
        fields["tool_detected"] = tool

    was_tarpitted = bool(identity.get("tarpit_active"))
    should_tarpit = scoring.should_tarpit(new_score) and not is_exempt(identity)
    if should_tarpit and not was_tarpitted:
        fields["tarpit_active"] = True

    identity = update_identity(ip, fields)

    alerting.alert_event(
        ip=ip,
        event_type=event_type,
        reason=reason,
        service=service,
        score_delta=float(points),
        cumulative_score=new_score,
        tool=tool,
        services=",".join(touched),
        payload=payload,
        tarpit_active=bool(identity.get("tarpit_active")),
        fake_hostname=identity.get("fake_hostname", ""),
        banned=bool(identity.get("banned")),
    )

    newly_banned = False
    if scoring.is_bannable(new_score) and not identity.get("banned"):
        ban(ip, score=new_score, reason=event_type, tool=tool,
            services=",".join(touched))
        newly_banned = True

    return {
        "old_score": old_score,
        "new_score": new_score,
        "event": event,
        "banned": newly_banned or bool(identity.get("banned")),
        "tarpitted": bool(identity.get("tarpit_active")),
        "identity": identity,
    }


def score_named_event(ip: str, event_type: str, payload: str = "",
                      tool: str = "", service: str = "") -> Dict[str, Any]:
    """score_event() with points and reason looked up from the scoring table."""
    from . import scoring
    points, reason = scoring.get_score(event_type)
    return score_event(ip, points, event_type, reason, payload=payload,
                       tool=tool, service=service)


def activate_tarpit(ip: str, reason: str = "Threshold reached",
                    service: str = "") -> Dict[str, Any]:
    """Flag an IP for slow-drain treatment across every service."""
    from . import alerting

    identity = get_or_create_identity(ip)
    if identity.get("tarpit_active"):
        return identity
    # An operator release outranks the automatic threshold until it expires --
    # otherwise the first service to score them puts the tarpit straight back
    # and the release was never real.
    if is_exempt(identity):
        return identity

    identity = update_identity(ip, {"tarpit_active": True,
                                    "tarpit_exempt_until": 0})
    alerting.alert_event(
        ip=ip,
        event_type="TARPIT_ENGAGED",
        reason=reason,
        service=service,
        cumulative_score=float(identity.get("score") or 0),
        tool=identity.get("tool_detected") or "",
        services=",".join(identity.get("services_touched") or []),
        tarpit_active=True,
        fake_hostname=identity.get("fake_hostname", ""),
    )
    return identity


RELEASE_SECONDS = int(os.getenv("HONEYPOT_TARPIT_RELEASE_SECONDS", "3600"))


def release_tarpit(ip: str, reason: str = "Operator release",
                   seconds: float = None) -> Dict[str, Any]:
    """Drop an IP out of the tarpit, and keep it out for a while.

    The counterpart to activate_tarpit, for false positives and for releasing
    someone deliberately. The score is left alone -- it is the record of what
    they did and clearing it would lose that -- but leaving it alone is also
    why clearing the flag on its own achieves nothing: the score is still over
    the threshold, so the next scored event re-engages the tarpit in the same
    second the attacker reconnects.

    So the release is an exemption with a deadline rather than a flag flip. It
    expires on its own, because a permanent release made by accident is
    invisible afterwards: the address simply never gets tarpitted again and
    nothing on the dashboard says why.
    """
    from . import alerting

    window = RELEASE_SECONDS if seconds is None else seconds
    identity = update_identity(ip, {"tarpit_active": False,
                                    "tarpit_exempt_until": time.time() + window})
    alerting.alert_event(
        ip=ip,
        event_type="TARPIT_RELEASED",
        reason=reason,
        cumulative_score=float(identity.get("score") or 0),
        tarpit_active=False,
    )
    return identity


def is_exempt(identity: Dict[str, Any]) -> bool:
    """Whether an operator has released this address from the tarpit.

    Clearing `tarpit_active` alone lasts one packet: the score is unchanged, so
    the next scored event puts it straight back. This is what makes the
    dashboard's release button mean what it says, and it expires on its own so
    a release cannot silently become permanent.
    """
    try:
        return float(identity.get("tarpit_exempt_until") or 0) > time.time()
    except (TypeError, ValueError):
        return False


def is_tarpitted(ip: str) -> bool:
    # Checked here as well as in score_event: an operator who was flagged before
    # being added to the ignore list would otherwise stay tarpitted forever,
    # since the flag already sits in their stored identity. The symptom is a
    # blank terminal on your own honeypot, which is the tarpit working.
    if is_ignored(ip):
        return False
    identity = get_or_create_identity(ip)
    if is_exempt(identity):
        return False
    return bool(identity.get("tarpit_active"))


def is_banned(ip: str) -> bool:
    if is_ignored(ip):
        return False
    client = _client()
    if client is None:
        return bool(_fallback(ip).get("banned"))
    try:
        return client.exists(f"hp:banned:{hash_ip(ip)}") > 0
    except Exception:
        return False


def ban(ip: str, score: float = 0, reason: str = "MANUAL", tool: str = "",
        services: str = "", ttl: int = BAN_TTL) -> None:
    """Ban an IP and emit the fail2ban line that drives the host firewall."""
    from . import alerting

    client = _client()
    if client is not None:
        try:
            client.setex(f"hp:banned:{hash_ip(ip)}", ttl, "1")
        except Exception:
            pass
    update_identity(ip, {"banned": True, "rickroll": True})
    alerting.log_ban_event(ip, score=score, reason=reason, tool=tool, services=services)


def unban(ip: str) -> None:
    client = _client()
    if client is not None:
        try:
            client.delete(f"hp:banned:{hash_ip(ip)}")
        except Exception:
            pass
    update_identity(ip, {"banned": False, "rickroll": False})


def record_credential(ip: str, username: str, password: str, service: str) -> int:
    """Store an attempted credential pair. Returns unique password count for this IP."""
    identity = get_or_create_identity(ip)
    creds = list(identity.get("credentials") or [])
    creds.append({
        "timestamp": _now(),
        "username": username[:128],
        "password": password[:128],
        "service": service,
    })
    update_identity(ip, {"credentials": creds[-MAX_HISTORY:]})
    return len({c.get("password") for c in creds})


def detect_spray(ip: str, window_seconds: int = 600, threshold: int = 5) -> bool:
    """True when an IP tried more than `threshold` distinct passwords in the window."""
    identity = get_or_create_identity(ip)
    cutoff = time.time() - window_seconds
    recent = set()
    for cred in identity.get("credentials") or []:
        try:
            ts = datetime.fromisoformat(cred["timestamp"]).timestamp()
        except Exception:
            continue
        if ts >= cutoff:
            recent.add(cred.get("password"))
    return len(recent) > threshold


class IdentityManager:
    """Thin object wrapper for services that prefer an instance."""

    def __init__(self, redis_host: str = REDIS_HOST, redis_port: int = REDIS_PORT):
        global REDIS_HOST, REDIS_PORT
        REDIS_HOST, REDIS_PORT = redis_host, redis_port

    get_or_create = staticmethod(get_or_create_identity)
    update = staticmethod(update_identity)
    score_event = staticmethod(score_event)
    score_named_event = staticmethod(score_named_event)
    activate_tarpit = staticmethod(activate_tarpit)
    release_tarpit = staticmethod(release_tarpit)
    is_tarpitted = staticmethod(is_tarpitted)
    is_banned = staticmethod(is_banned)
    ban = staticmethod(ban)
    unban = staticmethod(unban)
    touch_service = staticmethod(touch_service)
    record_credential = staticmethod(record_credential)
    detect_spray = staticmethod(detect_spray)
