"""Pluggable LLM provider abstraction (spec §3).

Phase 0/1 ships the interface plus a dependency-free :class:`StaticProvider`
so the LLM plumbing is exercisable with zero LLM dependency. The Claude /
Ollama / OpenAI-compatible providers are Phase 2 and currently raise
``NotImplementedError`` if instantiated/used (see LIMITATIONS.md).
"""

from deceptinet.engine.providers.base import LLMProvider, PromptContext
from deceptinet.engine.providers.static import StaticProvider

__all__ = ["LLMProvider", "PromptContext", "StaticProvider", "get_provider"]


def get_provider(name: str, **kwargs):
    """Factory for LLM providers. Only ``static`` is usable in Phase 1."""
    if name == "static":
        return StaticProvider(**kwargs)
    if name in ("claude", "ollama", "openai_compat"):
        # Imported lazily so missing optional SDKs don't break import of the
        # package; each raises a clear NOT IMPLEMENTED error when used.
        from deceptinet.engine.providers import claude, ollama, openai_compat

        return {
            "claude": claude.ClaudeProvider,
            "ollama": ollama.OllamaProvider,
            "openai_compat": openai_compat.OpenAICompatProvider,
        }[name](**kwargs)
    raise ValueError(f"unknown LLM provider: {name!r}")
