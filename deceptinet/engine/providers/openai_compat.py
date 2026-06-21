"""OpenAI-compatible endpoint provider — NOT IMPLEMENTED (Phase 2).

Covers any server exposing the OpenAI chat-completions API shape (vLLM, LM
Studio, llama.cpp server, etc.). See LIMITATIONS.md.
"""

from __future__ import annotations

from deceptinet.engine.providers.base import LLMProvider, ProviderResult, PromptContext

_MSG = (
    "OpenAICompatProvider is NOT IMPLEMENTED yet (Phase 2). "
    "Use provider 'static' in Phase 1."
)


class OpenAICompatProvider(LLMProvider):
    name = "openai_compat"

    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError(_MSG)

    async def generate(self, ctx: PromptContext) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError(_MSG)
