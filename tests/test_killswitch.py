"""Kill switch + egress probe (containment layer, spec §2.3)."""

from __future__ import annotations

from deceptinet.containment.egress import probe_egress
from deceptinet.containment.killswitch import KillSwitch


def test_killswitch_engage_disengage(tmp_path):
    ks = KillSwitch(tmp_path / "run" / "deceptinet.stop")
    assert ks.is_engaged() is False
    ks.engage(reason="unit-test")
    assert ks.is_engaged() is True
    assert "kill switch engaged" in ks.path.read_text()
    ks.disengage()
    assert ks.is_engaged() is False


def test_killswitch_idempotent(tmp_path):
    ks = KillSwitch(tmp_path / "deceptinet.stop")
    ks.disengage()  # no error when absent
    ks.engage()
    ks.engage()  # no error when present
    assert ks.is_engaged()


def test_egress_probe_to_blackhole_is_blocked():
    # 192.0.2.0/24 (TEST-NET-1, RFC 5737) is reserved + unroutable, so this must
    # not connect within the timeout regardless of the host's network policy.
    result = probe_egress(host="192.0.2.1", port=9, timeout=1.0)
    assert result.locked_down is True
    assert result.reachable is False
