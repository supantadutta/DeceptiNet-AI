"""POP3 honeypot end-to-end (vanilla mode)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from deceptinet.config.models import AuthConfig
from deceptinet.containment.killswitch import KillSwitch
from deceptinet.datastore.models import Credential, Event, Session
from deceptinet.services.pop3.server import POP3Honeypot
from deceptinet.telemetry.recorder import TelemetryRecorder

from tests.conftest import make_test_config

pytestmark = pytest.mark.asyncio


async def _read_until_dot(reader) -> bytes:
    data = b""
    while True:
        line = await reader.readline()
        data += line
        if line in (b".\r\n", b".\n") or not line:
            break
    return data


async def test_pop3_capture(datastore, tmp_path):
    cfg = make_test_config(auth=AuthConfig(accept_after_attempts=1, accept_credentials=[]))
    hp = POP3Honeypot(cfg, TelemetryRecorder(datastore), KillSwitch(tmp_path / "stop"))
    await hp.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", hp.bound_port)
        assert b"+OK" in await reader.readline()

        async def cmd(line: str) -> bytes:
            writer.write(line.encode() + b"\r\n")
            await writer.drain()
            return await reader.readline()

        assert b"+OK" in await cmd("USER alice")
        assert b"+OK" in await cmd("PASS s3cr3t")          # captured + accepted
        stat = await cmd("STAT")
        assert stat.startswith(b"+OK 2 ")                  # 2 canned messages
        writer.write(b"LIST\r\n"); await writer.drain()
        listing = await _read_until_dot(reader)
        assert b"1 " in listing and listing.rstrip().endswith(b".")
        writer.write(b"RETR 1\r\n"); await writer.drain()
        msg = await _read_until_dot(reader)
        assert b"Subject:" in msg
        await cmd("QUIT")
        writer.close()
    finally:
        await hp.stop()

    with datastore.session() as s:
        sess = s.scalars(select(Session)).first()
        assert sess.service == "pop3"
        creds = s.scalars(select(Credential)).all()
        assert any(c.username == "alice" and c.password == "s3cr3t" for c in creds)
        cmds = [e.command for e in s.scalars(select(Event).order_by(Event.seq)).all()]
        assert "USER alice" in cmds and "STAT" in cmds and "RETR 1" in cmds
