"""Per-session metrics for the LLM-vs-vanilla comparison (Phase 5, spec §5).

Each metric is computed from real captured rows. Metrics are grouped into the
three research questions:
  * Engagement (RQ1): duration, interaction count, depth, % exceeding N.
  * Intelligence (RQ2): distinct commands, distinct ATT&CK techniques, IOC count,
    novel-payload count, credentials harvested.
  * Cost/latency (RQ3): mean/p95 response latency, LLM tokens, cache-hit rate.

No fabrication: a session with no activity produces zeros/empties, not invented
values.
"""

from __future__ import annotations

import numpy as np
from sqlalchemy import select

from deceptinet.datastore.db import Datastore
from deceptinet.datastore.models import Credential, Event, IOC, Session, Technique

_CMD_TYPES = {"command", "exec_command", "http_request", "mysql_query", "mysql_command"}

# Threshold for the "% of sessions exceeding N interactions" engagement metric.
DEPTH_THRESHOLD_N = 5

# The metrics compared between modes, grouped by RQ (used by the harness).
ENGAGEMENT_METRICS = ["duration_s", "interaction_count", "session_depth", "exceeded_n"]
INTELLIGENCE_METRICS = [
    "distinct_commands", "distinct_techniques", "ioc_count",
    "novel_payload_count", "credential_count",
]
COST_METRICS = ["mean_latency_ms", "p95_latency_ms", "llm_tokens", "cache_hit_rate"]
ALL_METRICS = ENGAGEMENT_METRICS + INTELLIGENCE_METRICS + COST_METRICS


def session_metrics(session, events, credentials, techniques, iocs) -> dict:
    cmd_events = [e for e in events if e.event_type in _CMD_TYPES]
    commands = [(e.command or "").strip() for e in cmd_events if e.command]
    base_names = {c.split()[0] for c in commands if c.split()}

    latencies = [e.latency_ms for e in cmd_events if e.latency_ms is not None]
    tokens = 0
    cache_hits = 0
    cache_known = 0
    for e in events:
        meta = e.meta if isinstance(e.meta, dict) else {}
        tokens += (meta.get("input_tokens") or 0) + (meta.get("output_tokens") or 0)
        ch = e.cache_hit if e.cache_hit is not None else meta.get("cache_hit")
        if ch is not None:
            cache_known += 1
            if ch:
                cache_hits += 1

    return {
        "session_id": session.id,
        "mode": session.mode,
        "service": session.service,
        "classification": session.session_classification or "unknown",
        "src_ip": session.src_ip,
        # Engagement (RQ1)
        "duration_s": float(session.duration_s) if session.duration_s is not None else 0.0,
        "interaction_count": len(cmd_events),
        "session_depth": len(base_names),
        "exceeded_n": 1 if len(cmd_events) > DEPTH_THRESHOLD_N else 0,
        # Intelligence (RQ2)
        "distinct_commands": len(set(commands)),
        "distinct_techniques": len({t.technique_id for t in techniques}),
        "ioc_count": len(iocs),
        "novel_payload_count": sum(1 for i in iocs if i.ioc_type == "payload_url"),
        "credential_count": len(credentials),
        # Cost / latency (RQ3)
        "mean_latency_ms": float(np.mean(latencies)) if latencies else 0.0,
        "p95_latency_ms": float(np.percentile(latencies, 95)) if latencies else 0.0,
        "llm_tokens": int(tokens),
        "cache_hit_rate": (cache_hits / cache_known) if cache_known else 0.0,
    }


def collect_metrics(datastore: Datastore, experiment_id: str | None = None) -> list[dict]:
    with datastore.session() as s:
        q = select(Session)
        if experiment_id:
            q = q.where(Session.experiment_id == experiment_id)
        sessions = s.scalars(q).all()
        rows = []
        for sess in sessions:
            events = s.scalars(
                select(Event).where(Event.session_id == sess.id).order_by(Event.seq)
            ).all()
            creds = s.scalars(select(Credential).where(Credential.session_id == sess.id)).all()
            techs = s.scalars(select(Technique).where(Technique.session_id == sess.id)).all()
            iocs = s.scalars(select(IOC).where(IOC.session_id == sess.id)).all()
            rows.append(session_metrics(sess, events, creds, techs, iocs))
        return rows


def return_visit_rate(rows: list[dict]) -> dict[str, float]:
    """Fraction of distinct source IPs (per mode) seen in more than one session."""
    by_mode: dict[str, dict[str, int]] = {}
    for r in rows:
        by_mode.setdefault(r["mode"], {}).setdefault(r["src_ip"], 0)
        by_mode[r["mode"]][r["src_ip"]] += 1
    out = {}
    for mode, ips in by_mode.items():
        if ips:
            out[mode] = sum(1 for c in ips.values() if c > 1) / len(ips)
    return out
