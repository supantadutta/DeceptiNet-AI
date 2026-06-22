"""MySQL honeypot: handshake, credential capture, and a COM_QUERY result set."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from deceptinet.containment.killswitch import KillSwitch
from deceptinet.datastore.models import Credential, Event, Session
from deceptinet.services.mysql import protocol as proto
from deceptinet.services.mysql.server import MySQLHoneypot
from deceptinet.telemetry.recorder import TelemetryRecorder

from tests.conftest import make_test_config

pytestmark = pytest.mark.asyncio


def _handshake_response(username: str) -> bytes:
    caps = (0x00000200).to_bytes(4, "little")      # CLIENT_PROTOCOL_41
    max_packet = (16777216).to_bytes(4, "little")
    charset = b"\x21"
    reserved = b"\x00" * 23
    return caps + max_packet + charset + reserved + username.encode() + b"\x00" + b"\x00"


async def test_mysql_handshake_auth_and_query(datastore, tmp_path):
    cfg = make_test_config()
    hp = MySQLHoneypot(cfg, TelemetryRecorder(datastore), KillSwitch(tmp_path / "stop"))
    await hp.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", hp.bound_port)

        # 1) initial handshake from server
        _seq, payload = await proto.read_packet(reader)
        assert payload[0] == 0x0A                  # protocol version 10
        assert b"8.0.35" in payload                # plausible server version

        # 2) client handshake response -> server OK
        writer.write(proto.frame(_handshake_response("root"), 1))
        await writer.drain()
        _seq, ok = await proto.read_packet(reader)
        assert ok[0] == 0x00                       # OK packet (auth accepted)

        # 3) COM_QUERY SELECT VERSION()
        writer.write(proto.frame(b"\x03" + b"select version()", 0))
        await writer.drain()
        collected = b""
        for _ in range(8):
            try:
                _s, p = await asyncio.wait_for(proto.read_packet(reader), 2.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break
            collected += p
            if b"8.0.35" in p:
                break
        assert b"8.0.35" in collected              # version returned as a row value

        # 4) COM_QUIT
        writer.write(proto.frame(b"\x01", 0))
        await writer.drain()
        writer.close()
    finally:
        await hp.stop()

    with datastore.session() as s:
        sess = s.scalars(select(Session)).first()
        assert sess.service == "mysql"
        creds = s.scalars(select(Credential)).all()
        assert any(c.username == "root" for c in creds)
        ev = s.scalars(select(Event).where(Event.event_type == "mysql_query")).first()
        assert ev is not None and ev.command == "select version()"


async def test_protocol_lenenc_roundtrip():
    # Internal consistency of the encoders the result-set builder relies on.
    assert proto.lenenc_int(5) == b"\x05"
    assert proto.lenenc_int(300)[0] == 0xFC
    assert proto.lenenc_str("hi") == b"\x02hi"
    rs = proto.build_result_set(["a", "b"], [["1", "2"], ["3", "4"]])
    # column-count + 2 col defs + EOF + 2 rows + EOF = 7 payloads
    assert len(rs) == 7
