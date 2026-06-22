"""MITRE ATT&CK technique mapper (Phase 4, spec §4).

Maps observed behaviours in a captured session to ATT&CK techniques via a
transparent rules table (regex over commands + a few session-level rules). Each
hit records the matching evidence. This is a heuristic indicator mapper, not a
validated detection engine — coverage and precision caveats are in LIMITATIONS.md.

Operates on stored data only; no network, no fabrication.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CMD_TYPES = {"command", "exec_command", "mysql_query", "mysql_command"}


@dataclass
class Technique:
    id: str
    name: str
    evidence: str


# (technique_id, name, compiled regex over a command line)
_RULES: list[tuple[str, str, re.Pattern]] = [
    ("T1059", "Command and Scripting Interpreter", re.compile(r".+")),  # any command
    ("T1083", "File and Directory Discovery", re.compile(r"\b(ls|dir|find|locate|tree)\b", re.I)),
    ("T1082", "System Information Discovery",
     re.compile(r"\b(uname|lscpu|lsb_release|hostnamectl|free|df|/proc/(cpuinfo|version|meminfo))\b", re.I)),
    ("T1033", "System Owner/User Discovery", re.compile(r"\b(whoami|\bid\b|who|^w$|last)\b", re.I)),
    ("T1087", "Account Discovery", re.compile(r"(/etc/passwd|getent\s+passwd|/etc/shadow)", re.I)),
    ("T1105", "Ingress Tool Transfer", re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b", re.I)),
    ("T1222", "File and Directory Permissions Modification", re.compile(r"\b(chmod|chown|chattr)\b", re.I)),
    ("T1053", "Scheduled Task/Job", re.compile(r"\b(crontab|\bat\b|systemd-run)\b", re.I)),
    ("T1136", "Create Account", re.compile(r"\b(useradd|adduser|usermod)\b", re.I)),
    ("T1070", "Indicator Removal", re.compile(r"(rm\s+-rf|history\s+-c|shred|>\s*/var/log)", re.I)),
    ("T1057", "Process Discovery", re.compile(r"\b(ps|top|htop|pgrep)\b", re.I)),
    ("T1018", "Remote System Discovery", re.compile(r"\b(arp|ping|traceroute)\b", re.I)),
    ("T1046", "Network Service Scanning", re.compile(r"\b(netstat|ss|nmap|masscan)\b", re.I)),
    ("T1496", "Resource Hijacking", re.compile(r"(xmrig|minerd|stratum\+tcp|cryptonight|--donate-level)", re.I)),
    ("T1496", "Resource Hijacking", re.compile(r"\bpool\b.*\b(mine|miner|monero|xmr)\b", re.I)),
    ("T1562", "Impair Defenses", re.compile(r"(iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+stop\s+(firewalld|ufw))", re.I)),
    ("T1048", "Exfiltration Over Alternative Protocol", re.compile(r"\b(nc|ncat|netcat)\b.*\b\d{2,5}\b", re.I)),
]


def map_techniques(events, credentials) -> list[Technique]:
    techniques: dict[str, Technique] = {}

    def add(tid: str, name: str, evidence: str) -> None:
        if tid not in techniques:
            techniques[tid] = Technique(tid, name, evidence[:300])

    cmd_events = [e for e in events if e.event_type in _CMD_TYPES]
    for e in cmd_events:
        cmd = (e.command or "").strip()
        if not cmd:
            continue
        for tid, name, pat in _RULES:
            if pat.search(cmd):
                add(tid, name, cmd)

    # Session-level: brute force from repeated/failed credential attempts.
    if len(credentials) >= 3 or any(not c.accepted for c in credentials):
        add("T1110", "Brute Force", f"{len(credentials)} credential attempt(s)")
    if any(c.accepted for c in credentials):
        add("T1078", "Valid Accounts", "accepted a (honeypot) credential")

    # HTTP attack-probe hints (recorded by the HTTP adapter) -> exploitation TTPs.
    for e in events:
        meta = e.meta if isinstance(e.meta, dict) else {}
        hints = meta.get("attack_hints") or []
        if hints:
            add("T1190", "Exploit Public-Facing Application", f"{e.command} [{','.join(hints)}]")
        if "webshell" in hints:
            add("T1505.003", "Server Software Component: Web Shell", e.command or "")

    # MySQL recon.
    if any(e.event_type in ("mysql_query", "mysql_command") for e in events):
        for e in events:
            if e.command and re.search(r"information_schema|show\s+databases|show\s+tables", e.command, re.I):
                add("T1213", "Data from Information Repositories", e.command)
                break

    return sorted(techniques.values(), key=lambda t: t.id)
