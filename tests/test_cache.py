"""Response cache (spec §2.2)."""

from __future__ import annotations

from deceptinet.engine.cache import ResponseCache


def test_exact_hit_and_miss():
    c = ResponseCache(semantic=False)
    assert c.get("p", "ls") is None
    c.put("p", "ls", "out\n")
    assert c.get("p", "ls") == "out\n"
    assert c.get("p", "pwd") is None
    s = c.stats()
    assert s["hits"] == 1 and s["misses"] == 2 and s["size"] == 1


def test_semantic_normalises_whitespace():
    c = ResponseCache(semantic=True)
    c.put("p", "ls   -la", "X\n")
    assert c.get("p", "ls -la") == "X\n"  # whitespace-normalised match


def test_persona_scoped():
    c = ResponseCache(semantic=False)
    c.put("ubuntu", "id", "root\n")
    assert c.get("debian", "id") is None


def test_disabled_is_noop():
    c = ResponseCache(enabled=False)
    c.put("p", "ls", "x")
    assert c.get("p", "ls") is None


def test_eviction_fifo():
    c = ResponseCache(semantic=False, maxsize=2)
    c.put("p", "a", "1")
    c.put("p", "b", "2")
    c.put("p", "c", "3")  # evicts "a"
    assert c.get("p", "a") is None
    assert c.get("p", "c") == "3"
