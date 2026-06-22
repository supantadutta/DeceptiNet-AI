"""Session classifier (Phase 4, spec §2.1).

Labels a session ``automated | semi_interactive | human_like | unknown`` with a
confidence score, from transparent, documented heuristics over the captured
telemetry. This module's quality directly determines whether RQ1 is answerable,
so the features and thresholds are explicit (module constants) and every verdict
carries human-readable ``reasons``.

IMPORTANT (also in LIMITATIONS.md): the thresholds below are reasoned defaults,
NOT empirically calibrated against a labelled corpus. They are a starting point
to be validated/tuned in the analysis phase — not ground truth.

Operates on already-stored data; makes no network calls and fabricates nothing.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# Event types that count as "an attacker action" for timing/sequence features.
_CMD_TYPES = {"command", "exec_command", "http_request", "mysql_query", "mysql_command"}

# Definitive scanner/attack-tool fingerprints (in SSH client version or HTTP
# user-agent): their presence is treated as conclusive evidence of automation.
_SCANNER_FINGERPRINTS = [
    "masscan", "zgrab", "zmap", "nmap", "sqlmap", "hydra", "medusa", "ncrack",
    "nikto", "gobuster", "dirbuster", "wpscan", "nuclei", "censys", "httpx",
]
# Client-library fingerprints: strong (not conclusive) automation evidence — a
# human could be driving a script through these.
_CLIENT_LIB_FINGERPRINTS = [
    "libssh", "paramiko", "go-http", "golang", "python-requests", "okhttp",
    "curl/", "wget/", "russh", "jsch", "scrapy", "bot",
]

# A few classic fixed bot-script subsequences (IoT/Mirai-style staging).
_BOT_SCRIPT_HINTS = [
    re.compile(r"cd\s+/tmp.*(wget|curl|tftp)", re.I | re.S),
    re.compile(r"chmod\s+\+?x.*\./", re.I | re.S),
    re.compile(r"/bin/busybox", re.I),
    re.compile(r"\benable\b.*\bsystem\b.*\bshell\b", re.I | re.S),
]

# Thresholds (documented; tune in analysis).
_FAST_INTERVAL_S = 0.5     # below this mean gap => machine-fast
_HUMAN_INTERVAL_S = 2.0    # above this mean gap => human-paced
_REGULAR_CV = 0.25         # coefficient of variation below this => very regular
_IRREGULAR_CV = 0.70       # above this => human-irregular


@dataclass
class ClassificationResult:
    label: str
    confidence: float
    automation_score: float
    features: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def _std(xs, mean):
    if len(xs) < 2:
        return 0.0
    return math.sqrt(sum((x - mean) ** 2 for x in xs) / (len(xs) - 1))


def classify_session(session, events, credentials) -> ClassificationResult:
    """Classify one session. ``session`` has ``.term_type``/``.client_version``/
    ``.service``; ``events`` are ORM Event rows (``.event_type``/``.ts``/
    ``.command``/``.meta``); ``credentials`` are Credential rows."""
    cmd_events = [e for e in events if e.event_type in _CMD_TYPES]
    n = len(cmd_events)
    times = sorted(e.ts for e in cmd_events if e.ts is not None)
    intervals = [
        (times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)
    ]
    mean_interval = _mean(intervals)
    cv = None
    if mean_interval and mean_interval > 0:
        cv = _std(intervals, mean_interval) / mean_interval

    # Collect fingerprint sources: client version + any HTTP user-agent.
    fp_sources = [session.client_version or ""]
    for e in events:
        if e.meta and isinstance(e.meta, dict) and e.meta.get("user_agent"):
            fp_sources.append(str(e.meta["user_agent"]))
    fp_blob = " ".join(fp_sources).lower()
    matched_scanner = next((f for f in _SCANNER_FINGERPRINTS if f in fp_blob), None)
    matched_lib = next((f for f in _CLIENT_LIB_FINGERPRINTS if f in fp_blob), None)
    matched_fp = matched_scanner or matched_lib

    commands_blob = "\n".join(e.command or "" for e in cmd_events)
    bot_script = any(p.search(commands_blob) for p in _BOT_SCRIPT_HINTS)

    # Separate evidence for automation vs. human interaction. Absence of
    # automation evidence must NOT read as strong human evidence (and vice
    # versa) — that was a real misclassification source. Each accumulates only
    # positive signals.
    reasons: list[str] = []
    auto = 0.0
    human = 0.0

    if matched_lib:
        auto += 0.35
        reasons.append(f"client-library fingerprint: {matched_lib!r}")

    if session.service == "ssh":
        if session.term_type:
            human += 0.30
            reasons.append(f"interactive PTY allocated (term={session.term_type})")
        else:
            auto += 0.25
            reasons.append("no PTY (exec / non-interactive)")

    if n >= 3 and mean_interval is not None:
        if mean_interval < _FAST_INTERVAL_S:
            auto += 0.25
            reasons.append(f"machine-fast mean interval ({mean_interval:.2f}s)")
        elif mean_interval > _HUMAN_INTERVAL_S:
            human += 0.30
            reasons.append(f"human-paced mean interval ({mean_interval:.2f}s)")
        if cv is not None and n >= 4 and cv < _REGULAR_CV:
            auto += 0.20
            reasons.append(f"highly regular timing (cv={cv:.2f})")
        elif cv is not None and cv > _IRREGULAR_CV:
            human += 0.25
            reasons.append(f"irregular (human-like) timing (cv={cv:.2f})")

    if bot_script:
        auto += 0.20
        reasons.append("matches a known fixed bot-script pattern")

    auto = min(1.0, auto)
    human = min(1.0, human)

    features = {
        "n_commands": n,
        "mean_interval_s": round(mean_interval, 3) if mean_interval is not None else None,
        "interval_cv": round(cv, 3) if cv is not None else None,
        "term_type": session.term_type,
        "client_version": session.client_version,
        "scanner_fingerprint": matched_scanner,
        "client_lib_fingerprint": matched_lib,
        "bot_script_pattern": bot_script,
        "n_credentials": len(credentials),
        "automation_evidence": round(auto, 3),
        "human_evidence": round(human, 3),
    }

    # Decide label.
    confidence = 0.15  # default for low-signal / unknown
    if matched_scanner:
        label = "automated"
        reasons.insert(0, f"definitive scanner fingerprint: {matched_scanner!r}")
        confidence = 0.9
    elif n == 0:
        if matched_lib:
            label = "automated"
            reasons.append("automated-client fingerprint, no commands issued (probe)")
            confidence = 0.6
        else:
            label = "unknown"
            reasons.append("no commands issued; insufficient signal")
            confidence = 0.15
    elif auto >= 0.55 and auto >= human:
        label = "automated"
    elif human >= 0.40 and human > auto:
        label = "human_like"
    elif auto > 0 or human > 0:
        label = "semi_interactive"
    else:
        label = "unknown"
        reasons.append("no decisive automation or interaction signal")

    if label != "unknown" and not matched_scanner and not (n == 0):
        # Confidence reflects evidence strength + margin + data volume, NOT mere
        # closeness to an arbitrary midpoint.
        margin = abs(auto - human)
        data_factor = min(1.0, n / 5.0)
        confidence = round(
            min(1.0, 0.2 + 0.45 * margin + 0.2 * data_factor + (0.1 if matched_fp else 0.0)),
            3,
        )

    return ClassificationResult(
        label=label, confidence=confidence, automation_score=round(auto, 3),
        features=features, reasons=reasons,
    )


# Kept for back-compat with the Phase-1 stub import surface.
UNKNOWN = "unknown"


def classify(*args, **kwargs):  # pragma: no cover - thin alias
    return classify_session(*args, **kwargs)
