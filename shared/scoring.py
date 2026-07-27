"""Scoring constants and utility functions for honeypot events."""

import os

SCORES = {
    "CONNECTION_ANY": (1, "Initial contact"),
    "RECON_LS": (1, "Directory enumeration"),
    "READ_PASSWD": (3, "Read /etc/passwd"),
    "READ_SHADOW": (5, "Read /etc/shadow"),
    "PROCESS_ENUM": (2, "Process enumeration"),
    "NETWORK_ENUM": (3, "Network enumeration"),
    "DOCKER_K8S_ENUM": (4, "Container/orchestrator enumeration"),
    "SQLI_BASIC": (8, "SQL injection pattern"),
    "SQLI_UNION_BLIND": (10, "UNION/blind SQL injection"),
    "SQLI_OOB": (12, "Out-of-band SQL injection attempt"),
    "PHP_EVAL_ATTEMPT": (7, "PHP code execution attempt"),
    "FILE_UPLOAD": (8, "Malicious file upload"),
    "WEBSHELL_CMD": (2, "Webshell command issued"),
    # Clearing immutable flags on ~/.ssh, rewriting authorized_keys, disabling
    # history. Weighted well above ordinary recon: this is someone settling in.
    "PERSISTENCE_ATTEMPT": (8, "SSH persistence / anti-forensics attempt"),
    "REVERSE_SHELL": (12, "Reverse shell payload"),
    "CREDENTIAL_ATTEMPT": (2, "Login credential attempt"),
    "CREDENTIAL_SPRAY": (6, "Credential spraying"),
    "RATE_LIMIT_ABUSE": (4, "Rate limit exceeded"),
    # Deliberately low. One ordinary SMB scan fires this 8+ times -- NEGOTIATE,
    # SESSION_SETUP, then a TREE_CONNECT per share -- so at 5 points a piece of
    # pure background noise crossed the ban threshold in about five seconds,
    # while an operator actually exploring the web shell scores 2 per command.
    # At 2 points a single scan tarpits but does not ban; a scanner that keeps
    # coming back still accumulates its way there over three or so sessions.
    "SMB_ENUM": (2, "SMB share enumeration"),
    "RDP_CONNECT": (3, "RDP connection attempt"),
    "FTP_ANON": (2, "Anonymous FTP attempt"),
    "SMTP_RELAY": (6, "Open relay attempt"),
    "SCANNER_PATH_HIT": (2, "Known scanner path accessed"),
    "TARPIT_ENGAGED": (0, "Tarpit activated for IP"),
    "TOOL_SQLMAP": (5, "sqlmap detected"),
    "TOOL_METASPLOIT": (8, "Metasploit detected"),
    "TOOL_NUCLEI": (3, "Nuclei detected"),
    "TOOL_NIKTO": (3, "Nikto detected"),
    "TOOL_HYDRA": (4, "Hydra detected"),
    "TOOL_MASSCAN": (3, "Masscan detected"),
    "TOOL_OTHER": (2, "Automated scanner detected"),
}

BAN_THRESHOLD = int(os.getenv("HONEYPOT_BAN_THRESHOLD", "35"))
TARPIT_THRESHOLD = int(os.getenv("HONEYPOT_TARPIT_THRESHOLD", "5"))
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))


def get_score(event_type: str) -> tuple:
    """Get (points, description) for an event type."""
    return SCORES.get(event_type, (0, "Unknown event"))


def is_bannable(total_score: float) -> bool:
    """Check if IP should be banned based on cumulative score."""
    return total_score >= BAN_THRESHOLD


def should_tarpit(total_score: float) -> bool:
    """Check if IP should be tarpitted based on score."""
    return total_score >= TARPIT_THRESHOLD
