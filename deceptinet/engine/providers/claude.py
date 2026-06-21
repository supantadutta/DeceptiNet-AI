"""Claude API provider — NOT IMPLEMENTED (Phase 2).

Stubbed so the provider registry is complete and import-safe. Instantiating it
raises immediately rather than silently degrading, so a misconfiguration during
Phase 1 fails loud. See LIMITATIONS.md.
"""

from __future__ import annotations

from deceptinet.engine.providers.base import LLMProvider, ProviderResult, PromptContext

_MSG = "ClaudeProvider is NOT IMPLEMENTED yet (Phase 2). Use provider 'static' in Phase 1."


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError(_MSG)

    async def generate(self, ctx: PromptContext) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError(_MSG)
