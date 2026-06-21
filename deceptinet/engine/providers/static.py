"""StaticProvider — a no-LLM passthrough (spec §3, Phase 0 deliverable).

Returns a fixed, clearly-labelled canned string regardless of input. Its job is
to let the LLM-mode plumbing run end-to-end with zero LLM dependency (useful for
CI and as the configured ``fallback_provider``). It does NOT attempt to emulate
a shell — that's the vanilla engine's job.
"""

from __future__ import annotations

import time

from deceptinet.engine.providers.base import LLMProvider, ProviderResult, PromptContext

_CANNED = "static-provider: no LLM configured\n"


class StaticProvider(LLMProvider):
    name = "static"

    def __init__(self, canned_text: str = _CANNED) -> None:
        self._canned = canned_text

    async def generate(self, ctx: PromptContext) -> ProviderResult:
        start = time.perf_counter()
        return ProviderResult(
            text=self._canned,
            provider=self.name,
            model=None,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            meta={"deterministic": True},
        )
