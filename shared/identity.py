"""Fake machine identity generator and per-IP state cache.

Redis is the single source of truth. Whichever service sees an IP first writes
the identity; every other service reads it back, so an attacker who hits the web
shell and then SSH sees one consistent fake machine. Generation is seeded from
crc32(ip) so a lost cache regenerates the same values.

Every public function degrades to an in-process fallback if Redis is unreachable
rather than raising into a protocol handler.
"""

import hashlib
import json
import os
import random
import threading
import time
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis

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
IGNORE_IPS = {
    item.strip() for item in os.getenv("HONEYPOT_IGNORE_IPS", "").split(",")
    if item.strip()
}

HOSTNAME_POOL = [
    "prod-web-01", "prod-web-02", "prod-db-01", "prod-cache-01",
    "mail-srv-01", "api-gateway-01", "proxy-01", "app-node-03",
    "backup-srv", "monitoring-01", "vpn-gateway", "srv-colo-04",
]

KERNEL_POOL = [
    "5.15.0-86-generic", "5.15.0-91-generic", "5.10.0-21-amd64",
    "5.4.0-150-generic", "4.19.0-23-amd64", "6.1.0-13-amd64",
]

OS_POOL = [
    "Ubuntu 22.04.3 LTS", "Ubuntu 20.04.6 LTS", "Debian GNU/Linux 11 (bullseye)",
    "Debian GNU/Linux 12 (bookworm)", "CentOS Linux 7 (Core)", "AlmaLinux 8.9",
]

HUMAN_USERS = [
    ("jmarsh", "/home/jmarsh"), ("dkowalski", "/home/dkowalski"),
    ("rchen", "/home/rchen"), ("aokafor", "/home/aokafor"),
    ("tbergman", "/home/tbergman"), ("lnguyen", "/home/lnguyen"),
]

_local_cache: Dict[str, Dict[str, Any]] = {}
_local_lock = threading.Lock()
_redis_client: Optional[redis.Redis] = None
_redis_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_ip(ip: str) -> str:
    """Redis key component. MD5 here is an opaque identifier, not a security control."""
    return hashlib.md5(ip.encode()).hexdigest()


def _client() -> Optional[redis.Redis]:
    global _redis_client
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
                return None
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
        return {"type": "file", "mode": mode, "size": size}

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
                                "2024": d(**{
                                    "01": d(**{
                                        "strategic-plan-2024.pdf": f(284918),
                                    }),
                                }),
                            }),
                            "plugins": d(), "themes": d(),
                        }),
                        "uploads": d(),
                    }),
                }),
                "log": d(**{"syslog": f(1048576), "auth.log": f(204800)}),
                "backups": d(**{"db-backup-2024-01-14.sql.gz": f(48211904)}),
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
    client = _client()
    if client is None:
        return _fallback(ip)

    key = f"hp:identity:{hash_ip(ip)}"
    try:
        cached = client.get(key)
        if cached:
            return json.loads(cached)
        identity = _generate(ip)
        # NX so two services racing on the same IP agree on one identity.
        if not client.set(key, json.dumps(identity), ex=IDENTITY_TTL, nx=True):
            cached = client.get(key)
            if cached:
                return json.loads(cached)
        return identity
    except Exception:
        return _fallback(ip)


def update_identity(ip: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Merge fields into the stored identity and refresh its TTL."""
    identity = get_or_create_identity(ip)
    identity.update(fields)
    identity["last_seen"] = _now()

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

    if ip in IGNORE_IPS:
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
    should_tarpit = scoring.should_tarpit(new_score)
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

    identity = update_identity(ip, {"tarpit_active": True})
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


def is_tarpitted(ip: str) -> bool:
    # Checked here as well as in score_event: an operator who was flagged before
    # being added to the ignore list would otherwise stay tarpitted forever,
    # since the flag already sits in their stored identity. The symptom is a
    # blank terminal on your own honeypot, which is the tarpit working.
    if ip in IGNORE_IPS:
        return False
    return bool(get_or_create_identity(ip).get("tarpit_active"))


def is_banned(ip: str) -> bool:
    if ip in IGNORE_IPS:
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
    is_tarpitted = staticmethod(is_tarpitted)
    is_banned = staticmethod(is_banned)
    ban = staticmethod(ban)
    unban = staticmethod(unban)
    touch_service = staticmethod(touch_service)
    record_credential = staticmethod(record_credential)
    detect_spray = staticmethod(detect_spray)
