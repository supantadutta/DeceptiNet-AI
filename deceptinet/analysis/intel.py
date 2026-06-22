"""Per-session intelligence report (Phase 4, spec §4 "done when").

Runs the classifier + IOC extractor + ATT&CK mapper over a captured session and
emits a structured JSON-serialisable report. Optionally persists the results
(classification onto the session row; IOC/Technique rows), idempotently.

Reads only real captured rows — nothing is fabricated. A session with no
attacker activity yields a report that honestly says so.
"""

from __future__ import annotations

from sqlalchemy import delete, select

from deceptinet.datastore.db import Datastore
from deceptinet.datastore.models import Credential, Event, IOC, Session, Technique
from deceptinet.telemetry.attack_map import map_techniques
from deceptinet.telemetry.classifier import classify_session
from deceptinet.telemetry.ioc import extract_iocs


def analyze_session(datastore: Datastore, session_id: str, *, persist: bool = True) -> dict:
    with datastore.session() as s:
        sess = s.get(Session, session_id)
        if sess is None:
            raise KeyError(f"no such session: {session_id}")
        events = s.scalars(
            select(Event).where(Event.session_id == session_id).order_by(Event.seq)
        ).all()
        creds = s.scalars(
            select(Credential).where(Credential.session_id == session_id)
        ).all()

        cls = classify_session(sess, events, creds)
        iocs = extract_iocs(events, creds)
        techs = map_techniques(events, creds)

        report = {
            "session_id": sess.id,
            "experiment_id": sess.experiment_id,
            "service": sess.service,
            "mode": sess.mode,
            "src_ip": sess.src_ip,
            "src_port": sess.src_port,
            "started_at": sess.started_at.isoformat() if sess.started_at else None,
            "ended_at": sess.ended_at.isoformat() if sess.ended_at else None,
            "duration_s": sess.duration_s,
            "event_count": len(events),
            "classification": {
                "label": cls.label,
                "confidence": cls.confidence,
                "automation_score": cls.automation_score,
                "features": cls.features,
                "reasons": cls.reasons,
            },
            "credentials": [
                {"username": c.username, "password": c.password, "accepted": c.accepted}
                for c in creds
            ],
            "iocs": iocs,
            "attack_techniques": [
                {"id": t.id, "name": t.name, "evidence": t.evidence} for t in techs
            ],
        }

        if persist:
            sess.session_classification = cls.label
            sess.classification_confidence = cls.confidence
            merged = dict(sess.meta or {})
            merged["classification"] = {
                "label": cls.label,
                "confidence": cls.confidence,
                "automation_score": cls.automation_score,
                "reasons": cls.reasons,
            }
            sess.meta = merged
            # Idempotent: clear any prior analysis for this session.
            s.execute(delete(IOC).where(IOC.session_id == session_id))
            s.execute(delete(Technique).where(Technique.session_id == session_id))
            for ioc_type, values in iocs.items():
                for value in values:
                    s.add(IOC(session_id=session_id, ioc_type=ioc_type, value=value))
            for t in techs:
                s.add(Technique(
                    session_id=session_id, technique_id=t.id, name=t.name, evidence=t.evidence
                ))

        return report


def analyze_all(datastore: Datastore, *, persist: bool = True) -> list[dict]:
    with datastore.session() as s:
        ids = [row[0] for row in s.execute(select(Session.id)).all()]
    return [analyze_session(datastore, sid, persist=persist) for sid in ids]
