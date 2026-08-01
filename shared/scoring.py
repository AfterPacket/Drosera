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
    # Pulling a file off a share, as opposed to listing one. Weighted above
    # SMB_ENUM because a scanner enumerates and leaves, while fetching contents
    # is a deliberate choice about a specific file -- and someone working
    # through a share file by file reaches the ban threshold, which is right.
    "FILE_DOWNLOAD": (4, "File contents retrieved"),
    "WEBSHELL_CMD": (2, "Webshell command issued"),
    # Naming where the second stage lives is a step past running commands: it
    # is the point the session stops being reconnaissance and starts being an
    # attempted infection.
    "LOADER_URL": (6, "Second-stage retrieval URL disclosed"),
    # Clearing immutable flags on ~/.ssh, rewriting authorized_keys, disabling
    # history. Weighted well above ordinary recon: this is someone settling in.
    "PERSISTENCE_ATTEMPT": (8, "SSH persistence / anti-forensics attempt"),
    "REVERSE_SHELL": (12, "Reverse shell payload"),
    # Running something they just wrote. Distinct from a reverse shell and
    # weighted lower: fingerprinting scripts routinely write a trivial script
    # and run it purely to test whether the filesystem allows it, and scoring
    # that as a reverse shell banned them mid-probe.
    "DROPPED_BINARY_EXEC": (6, "Executed a file they created"),
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

# MITRE ATT&CK technique per event type, as (id, name).
#
# A separate table rather than a third element in SCORES: the score is a policy
# knob an operator tunes, and the technique is a fact about what the behaviour
# is. Tying them together would mean re-deciding the taxonomy every time
# somebody adjusts a weight.
#
# Only the events that genuinely correspond to a technique are listed. An
# unmapped event is left unmapped -- CONNECTION_ANY is a TCP connection, not
# T1021, and inflating the coverage would make the resulting chart a
# description of this table rather than of the traffic.
TECHNIQUES = {
    "CREDENTIAL_ATTEMPT": ("T1110", "Brute Force"),
    "CREDENTIAL_SPRAY": ("T1110.003", "Password Spraying"),
    "WEBSHELL_CMD": ("T1059", "Command and Scripting Interpreter"),
    "DROPPED_BINARY_EXEC": ("T1204.002", "User Execution: Malicious File"),
    "PHP_EVAL_ATTEMPT": ("T1059.004", "Unix Shell"),
    "REVERSE_SHELL": ("T1071", "Application Layer Protocol"),
    "LOADER_URL": ("T1105", "Ingress Tool Transfer"),
    "FILE_UPLOAD": ("T1105", "Ingress Tool Transfer"),
    "FILE_DOWNLOAD": ("T1005", "Data from Local System"),
    "PERSISTENCE_ATTEMPT": ("T1098.004", "SSH Authorized Keys"),
    "SQLI_BASIC": ("T1190", "Exploit Public-Facing Application"),
    "SQLI_UNION_BLIND": ("T1190", "Exploit Public-Facing Application"),
    "SQLI_OOB": ("T1190", "Exploit Public-Facing Application"),
    "SCANNER_PATH_HIT": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "SMB_ENUM": ("T1135", "Network Share Discovery"),
    "RECON_LS": ("T1083", "File and Directory Discovery"),
    "READ_PASSWD": ("T1003.008", "OS Credential Dumping: /etc/passwd"),
    "READ_SHADOW": ("T1003.008", "OS Credential Dumping: /etc/shadow"),
    "PROCESS_ENUM": ("T1057", "Process Discovery"),
    "NETWORK_ENUM": ("T1046", "Network Service Discovery"),
    "DOCKER_K8S_ENUM": ("T1613", "Container and Resource Discovery"),
    "SMTP_RELAY": ("T1071.003", "Mail Protocols"),
    "RATE_LIMIT_ABUSE": ("T1499", "Endpoint Denial of Service"),
    "TOOL_SQLMAP": ("T1595.002", "Vulnerability Scanning"),
    "TOOL_NUCLEI": ("T1595.002", "Vulnerability Scanning"),
    "TOOL_NIKTO": ("T1595.002", "Vulnerability Scanning"),
    "TOOL_METASPLOIT": ("T1588.002", "Obtain Capabilities: Tool"),
    "TOOL_HYDRA": ("T1110", "Brute Force"),
    "TOOL_MASSCAN": ("T1595.001", "Scanning IP Blocks"),
}

BAN_THRESHOLD = int(os.getenv("HONEYPOT_BAN_THRESHOLD", "35"))
TARPIT_THRESHOLD = int(os.getenv("HONEYPOT_TARPIT_THRESHOLD", "5"))
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))


def get_score(event_type: str) -> tuple:
    """Get (points, description) for an event type."""
    return SCORES.get(event_type, (0, "Unknown event"))


def get_technique(event_type: str):
    """(id, name) for an event type, or None where no technique applies."""
    return TECHNIQUES.get(event_type)


def is_bannable(total_score: float) -> bool:
    """Check if IP should be banned based on cumulative score."""
    return total_score >= BAN_THRESHOLD


def should_tarpit(total_score: float) -> bool:
    """Check if IP should be tarpitted based on score."""
    return total_score >= TARPIT_THRESHOLD
