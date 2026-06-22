"""End-to-end SSH honeypot test.

Connects a REAL asyncssh client to the honeypot, drives an interactive shell,
and asserts the full pipeline captured the session into the datastore with
timestamps, credentials, command events, and persisted filesystem state.

The session captured here is a *demonstration connection from our own test
client* — clearly not attacker data. It exists to prove the capture pipeline,
per the Phase 1 acceptance criteria.
"""

from __future__ import annotations

import asyncio

import asyncssh
import pytest
from sqlalchemy import select

from deceptinet.containment.killswitch import KillSwitch
from deceptinet.config.models import ContainmentConfig
from deceptinet.datastore.models import Credential, Event, Session
from deceptinet.engine.factory import get_engine
from deceptinet.services.ssh.server import SSHHoneypot
from deceptinet.telemetry.recorder import TelemetryRecorder

from tests.conftest import make_test_config

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def honeypot(datastore, tmp_path):
    cfg = make_test_config(
        containment=ContainmentConfig(
            egress="deny", kill_switch_file=str(tmp_path / "stop")
        )
    )
    hp = SSHHoneypot(
        cfg,
        get_engine(cfg),
        TelemetryRecorder(datastore),
        KillSwitch(cfg.containment.kill_switch_file),
        host_key_dir=str(tmp_path / "hostkeys"),
    )
    await hp.start()
    try:
        yield hp
    finally:
        await hp.stop()


async def _wait_until(honeypot, datastore, predicate, timeout: float = 5.0):
    """Poll until ``predicate(session)`` is satisfied.

    Probe-only sessions are finalized from the server's ``connection_lost``
    callback, which fires asynchronously after the client sees its error — so we
    drain + re-check rather than assuming a single drain suffices.
    """
    import time

    deadline = time.monotonic() + timeout
    while True:
        await honeypot.drain()
        with datastore.session() as s:
            if predicate(s):
                return
        if time.monotonic() > deadline:
            raise AssertionError("condition not met before timeout")
        await asyncio.sleep(0.05)


async def _drive_shell(port: int, commands: list[str]) -> str:
    async with asyncssh.connect(
        "127.0.0.1",
        port,
        username="root",
        password="root",
        known_hosts=None,
        client_keys=None,
    ) as conn:
        assert conn.get_extra_info("server_version", "").startswith("SSH-2.0-OpenSSH")
        proc = await conn.create_process(term_type="xterm-256color")
        for cmd in commands:
            proc.stdin.write(cmd + "\n")
        output = await proc.stdout.read()  # reads until server closes channel
        await proc.wait_closed()
        return output


async def test_full_capture_pipeline(honeypot, datastore):
    port = honeypot.bound_port
    assert port and port > 0

    commands = ["whoami", "mkdir loot", "ls", "cat /etc/passwd", "id", "exit"]
    output = await asyncio.wait_for(_drive_shell(port, commands), timeout=20)

    # The interactive shell actually responded.
    assert "root" in output

    await honeypot.drain()

    with datastore.session() as s:
        sessions = s.scalars(select(Session)).all()
        assert len(sessions) == 1
        sess = sessions[0]
        assert sess.mode == "vanilla"
        assert sess.service == "ssh"
        assert sess.src_ip == "127.0.0.1"
        assert sess.term_type == "xterm-256color"
        assert (sess.client_version or "").startswith("SSH-2.0-")
        assert sess.started_at is not None and sess.ended_at is not None
        assert sess.session_classification == "unknown"  # Phase 4 not done — honest

        # Credentials captured (root:root is auto-accepted).
        creds = s.scalars(
            select(Credential).where(Credential.session_id == sess.id)
        ).all()
        assert any(c.accepted and c.username == "root" for c in creds)

        # Command events captured with monotonic sequence + timestamps.
        events = s.scalars(
            select(Event).where(Event.session_id == sess.id).order_by(Event.seq)
        ).all()
        types = [e.event_type for e in events]
        assert types[0] == "login_success"
        cmd_events = [e for e in events if e.event_type == "command"]
        captured_cmds = [e.command for e in cmd_events]
        for expected in ["whoami", "mkdir loot", "ls", "cat /etc/passwd", "id"]:
            assert expected in captured_cmds
        assert all(e.ts is not None for e in events)
        assert [e.seq for e in events] == sorted(e.seq for e in events)

        # State consistency: the `ls` AFTER `mkdir loot` shows `loot`.
        ls_event = next(e for e in cmd_events if e.command == "ls")
        assert "loot" in (ls_event.response or "")

        # whoami response is correct.
        whoami_event = next(e for e in cmd_events if e.command == "whoami")
        assert whoami_event.response == "root\n"


async def test_exec_mode_capture(honeypot, datastore):
    """Non-interactive `ssh host 'cmd'` (the common bot pattern)."""
    port = honeypot.bound_port
    async with asyncssh.connect(
        "127.0.0.1", port, username="root", password="root",
        known_hosts=None, client_keys=None,
    ) as conn:
        result = await conn.run("uname -a", check=False)
        assert "Linux web-prod-01" in result.stdout

    await honeypot.drain()
    with datastore.session() as s:
        events = s.scalars(select(Event).where(Event.event_type == "exec_command")).all()
        assert any(e.command == "uname -a" for e in events)


async def test_probe_only_connection_is_recorded(honeypot, datastore):
    """A failed-auth probe (wrong password, one try) is still captured."""
    port = honeypot.bound_port
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect(
            "127.0.0.1", port, username="root", password="wrong-password",
            known_hosts=None, client_keys=None,
            # Only offer the one (wrong) password so auth fails on the first try.
            preferred_auth=["password"],
        )

    await _wait_until(
        honeypot, datastore,
        lambda s: s.scalars(select(Session)).first() is not None,
    )
    with datastore.session() as s:
        sessions = s.scalars(select(Session)).all()
        assert len(sessions) == 1
        assert sessions[0].meta and sessions[0].meta.get("probe_only") is True
        creds = s.scalars(select(Credential)).all()
        assert len(creds) >= 1
        assert all(c.accepted is False for c in creds)


async def test_llm_mode_serves_novel_command(datastore, tmp_path):
    """SSH in llm mode: a command vanilla can't handle gets an LLM response,
    captured with engine_mode=llm. Uses an injected fake provider (no network)."""
    from deceptinet.engine.llm import LLMEngine
    from tests.test_llm_engine import FakeProvider

    cfg = make_test_config(
        mode="llm",
        containment=ContainmentConfig(egress="deny", kill_switch_file=str(tmp_path / "stop")),
    )
    engine = LLMEngine(FakeProvider("custom-novel-tool v1.2.3\n"))
    hp = SSHHoneypot(
        cfg, engine, TelemetryRecorder(datastore),
        KillSwitch(cfg.containment.kill_switch_file),
        host_key_dir=str(tmp_path / "hostkeys"),
    )
    await hp.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1", hp.bound_port, username="root", password="root",
            known_hosts=None, client_keys=None,
        ) as conn:
            result = await conn.run("somenoveltool --version", check=False)
            assert "custom-novel-tool v1.2.3" in result.stdout
        await hp.drain()
    finally:
        await hp.stop()

    with datastore.session() as s:
        sess = s.scalars(select(Session)).first()
        assert sess.mode == "llm"
        ev = s.scalars(
            select(Event).where(Event.command == "somenoveltool --version")
        ).first()
        assert ev is not None
        assert ev.engine_mode == "llm"
        assert ev.meta and ev.meta.get("responder") == "llm"


async def test_kill_switch_refuses_connections(honeypot, datastore):
    honeypot.kill_switch.engage(reason="test")
    try:
        port = honeypot.bound_port
        with pytest.raises((asyncssh.Error, OSError, ConnectionError)):
            await asyncio.wait_for(
                asyncssh.connect(
                    "127.0.0.1", port, username="root", password="root",
                    known_hosts=None, client_keys=None,
                ),
                timeout=10,
            )
    finally:
        honeypot.kill_switch.disengage()
