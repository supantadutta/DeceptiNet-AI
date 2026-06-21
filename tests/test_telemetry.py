"""Telemetry recorder writes queryable rows to the datastore."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from deceptinet.datastore.models import Credential, Event, Session
from deceptinet.telemetry.recorder import TelemetryRecorder

pytestmark = pytest.mark.asyncio


async def test_records_session_credentials_and_events(datastore):
    rec = TelemetryRecorder(datastore)
    handle = await rec.open_session(
        experiment_id="test-exp",
        mode="vanilla",
        service="ssh",
        src_ip="203.0.113.7",
        src_port=44321,
        client_version="SSH-2.0-libssh2_1.10.0",
        term_type="xterm-256color",
    )
    await handle.record_credential("root", "hunter2", "password", accepted=False)
    await handle.record_credential("root", "root", "password", accepted=True)
    await handle.record_event("login_success", meta={"username": "root"})
    await handle.record_event(
        "command", command="whoami", response="root\n", exit_status=0,
        latency_ms=0.5, engine_mode="vanilla",
    )
    await handle.close()

    with datastore.session() as s:
        sessions = s.scalars(select(Session)).all()
        assert len(sessions) == 1
        sess = sessions[0]
        assert sess.experiment_id == "test-exp"
        assert sess.mode == "vanilla"
        assert sess.src_ip == "203.0.113.7"
        assert sess.session_classification == "unknown"  # honest default
        assert sess.ended_at is not None
        assert sess.event_count == 2

        creds = s.scalars(select(Credential).order_by(Credential.ts)).all()
        assert [c.password for c in creds] == ["hunter2", "root"]
        assert [c.accepted for c in creds] == [False, True]

        events = s.scalars(
            select(Event).where(Event.session_id == sess.id).order_by(Event.seq)
        ).all()
        assert [e.event_type for e in events] == ["login_success", "command"]
        assert events[1].command == "whoami"
        assert events[1].response == "root\n"
        assert events[0].seq == 1 and events[1].seq == 2


async def test_response_truncation(datastore):
    rec = TelemetryRecorder(datastore)
    handle = await rec.open_session(
        experiment_id="t", mode="vanilla", service="ssh",
        src_ip="198.51.100.2", src_port=1234,
    )
    big = "A" * 20000
    await handle.record_event("command", command="x", response=big)
    await handle.close()
    with datastore.session() as s:
        ev = s.scalars(select(Event)).first()
        assert len(ev.response) < len(big)
        assert ev.meta and ev.meta.get("response_truncated") is True
