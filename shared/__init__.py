"""Shared honeypot utilities: identity state, scoring, alerting, fake shell.

Imports are lazy, and that is load-bearing rather than tidiness. Eagerly
importing every submodule here meant that `from shared import loot` pulled in
identity.py, which imports redis -- so the intel container, which needs nothing
but stdlib and deliberately installs no packages, crashed on startup. The one
container with internet egress should not be made to carry a Redis client it
never calls.

Submodules still import normally (`from shared import alerting`); Python's own
machinery finds those without help. The names below are re-exported
conveniences, resolved on first access via PEP 562.
"""

import importlib
from typing import Any

# name -> submodule that defines it.
_EXPORTS = {
    "SessionRecorder": "alerting",
    "alert_event": "alerting",
    "log_ban_event": "alerting",
    "log_session_end": "alerting",
    "log_session_start": "alerting",
    "IdentityManager": "identity",
    "activate_tarpit": "identity",
    "ban": "identity",
    "detect_spray": "identity",
    "get_or_create_identity": "identity",
    "hash_ip": "identity",
    "is_banned": "identity",
    "is_tarpitted": "identity",
    "record_credential": "identity",
    "release_tarpit": "identity",
    "score_event": "identity",
    "score_named_event": "identity",
    "touch_service": "identity",
    "unban": "identity",
    "update_identity": "identity",
    "BAN_THRESHOLD": "scoring",
    "SCORES": "scoring",
    "TARPIT_THRESHOLD": "scoring",
    "get_score": "scoring",
    "is_bannable": "scoring",
    "should_tarpit": "scoring",
    "deadline": "tarpit",
    "drip": "tarpit",
    "log_hold": "tarpit",
    "stall": "tarpit",
}

_SUBMODULES = ("alerting", "identity", "ioc", "loot", "persona", "rickroll",
               "scoring", "tarpit")

__all__ = list(_EXPORTS) + list(_SUBMODULES)


def __getattr__(name: str) -> Any:
    if name in _SUBMODULES:
        return importlib.import_module(f".{name}", __name__)
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(f".{module}", __name__), name)


def __dir__():
    return sorted(__all__)
