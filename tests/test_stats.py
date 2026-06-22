"""Comparison statistics (Phase 5)."""

from __future__ import annotations

from deceptinet.analysis.stats import compare_groups, describe, effect_label


def test_describe():
    d = describe([1, 2, 3, 4, 100])
    assert d.n == 5
    assert d.median == 3
    assert d.p95 is not None and d.p95 > 4


def test_compare_detects_clear_difference():
    a = [1, 2, 3, 4, 5, 6]
    b = [10, 11, 12, 13, 14, 15]
    r = compare_groups("m", "all", a, b)
    assert r.status == "ok"
    assert r.p_value < 0.05
    assert r.effect_size_r > 0.5          # b clearly exceeds a
    assert r.ci_low is not None and r.ci_low > 0


def test_compare_no_difference():
    a = [5, 5, 5, 5, 5, 5]
    b = [5, 5, 5, 5, 5, 5]
    r = compare_groups("m", "all", a, b)
    assert r.status == "ok"
    assert r.p_value >= 0.05
    assert abs(r.effect_size_r) < 0.1


def test_insufficient_data():
    r = compare_groups("m", "all", [1, 2], [3, 4, 5, 6, 7])
    assert r.status == "insufficient_data"
    assert r.p_value is None


def test_effect_label():
    assert effect_label(None) == "n/a"
    assert effect_label(0.05) == "negligible"
    assert effect_label(0.2) == "small"
    assert effect_label(0.4) == "medium"
    assert effect_label(0.8) == "large"
