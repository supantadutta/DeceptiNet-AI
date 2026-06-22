"""HTTP honeypot end-to-end (vanilla mode) + attack-probe tagging."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from deceptinet.containment.killswitch import KillSwitch
from deceptinet.datastore.models import Event, Session
from deceptinet.services.http.server import HTTPHoneypot
from deceptinet.telemetry.recorder import TelemetryRecorder

from tests.conftest import make_test_config

pytestmark = pytest.mark.asyncio


async def _request(port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await reader.read()  # server sends Connection: close -> read to EOF
    writer.close()
    return data


@pytest.fixture
async def http(datastore, tmp_path):
    cfg = make_test_config()
    hp = HTTPHoneypot(cfg, TelemetryRecorder(datastore), KillSwitch(tmp_path / "stop"))
    await hp.start()
    try:
        yield hp
    finally:
        await hp.stop()


async def test_index_and_404(http):
    port = http.bound_port
    ok = await _request(port, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: nmap\r\n\r\n")
    assert b"200 OK" in ok and b"ShopFast" in ok
    nf = await _request(port, b"GET /secret.php HTTP/1.1\r\nHost: x\r\n\r\n")
    assert b"404 Not Found" in nf


async def test_login_template(http):
    resp = await _request(http.bound_port, b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n")
    assert b"200 OK" in resp and b"<form" in resp


async def test_sqli_probe_tagged(http, datastore):
    body = b"username=admin'+OR+'1'='1&password=x"
    raw = (
        b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    await _request(http.bound_port, raw)
    await http.drain()
    with datastore.session() as s:
        sess = s.scalars(select(Session)).first()
        assert sess.service == "http"
        ev = s.scalars(
            select(Event).where(Event.command == "POST /login").order_by(Event.seq.desc())
        ).first()
        assert ev is not None
        assert ev.meta and "sqli" in (ev.meta.get("attack_hints") or [])


async def test_user_agent_captured(http, datastore):
    await _request(http.bound_port, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.0\r\n\r\n")
    await http.drain()
    with datastore.session() as s:
        ev = s.scalars(select(Event).where(Event.command == "GET /")).first()
        assert ev.meta.get("user_agent") == "sqlmap/1.0"
