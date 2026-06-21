"""Ollama (local) provider — NOT IMPLEMENTED (Phase 2). See LIMITATIONS.md."""

from __future__ import annotations

from deceptinet.engine.providers.base import LLMProvider, ProviderResult, PromptContext

_MSG = "OllamaProvider is NOT IMPLEMENTED yet (Phase 2). Use provider 'static' in Phase 1."


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError(_MSG)

    async def generate(self, ctx: PromptContext) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError(_MSG)
