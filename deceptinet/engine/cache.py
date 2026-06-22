"""Response cache (spec §2.2) — serves common commands instantly.

This addresses latency-fingerprinting: cached responses return in microseconds,
making them timing-indistinguishable from a real host. The cache is per-process
and keyed by (persona, command).

Two match modes:
  * exact      — key on the raw command string.
  * "semantic" — key on a whitespace-normalised command (``ls   -la`` == ``ls -la``).
    NOTE: this is a *lightweight* normalisation, not embedding-based semantic
    similarity. True semantic caching (embeddings + nearest-neighbour) is NOT
    implemented — see LIMITATIONS.md.
"""

from __future__ import annotations


class ResponseCache:
    def __init__(self, enabled: bool = True, semantic: bool = True, maxsize: int = 4096) -> None:
        self.enabled = enabled
        self.semantic = semantic
        self.maxsize = maxsize
        self._store: dict[tuple[str, str], str] = {}
        self._order: list[tuple[str, str]] = []
        self.hits = 0
        self.misses = 0

    def _key(self, persona: str, command: str) -> tuple[str, str]:
        cmd = " ".join(command.split()).strip() if self.semantic else command
        return (persona, cmd)

    def get(self, persona: str, command: str) -> str | None:
        if not self.enabled:
            return None
        val = self._store.get(self._key(persona, command))
        if val is None:
            self.misses += 1
        else:
            self.hits += 1
        return val

    def put(self, persona: str, command: str, response: str) -> None:
        if not self.enabled:
            return
        key = self._key(persona, command)
        if key not in self._store and len(self._store) >= self.maxsize:
            oldest = self._order.pop(0)
            self._store.pop(oldest, None)
        if key not in self._store:
            self._order.append(key)
        self._store[key] = response

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "size": len(self._store),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": (self.hits / total) if total else 0.0,
        }
