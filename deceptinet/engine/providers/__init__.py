"""Pluggable LLM provider abstraction (spec §3).

Phase 2 implements Claude (official SDK), Ollama, and OpenAI-compatible
providers, plus the dependency-free StaticProvider (also the default
``fallback_provider``). The provider is selected by ``llm.provider`` in config.
"""

from deceptinet.engine.providers.base import (
    LLMProvider,
    ProviderError,
    ProviderResult,
    PromptContext,
)
from deceptinet.engine.providers.static import StaticProvider

__all__ = [
    "LLMProvider",
    "PromptContext",
    "ProviderResult",
    "ProviderError",
    "StaticProvider",
    "get_provider",
    "build_provider",
]


def get_provider(name: str, **kwargs) -> LLMProvider:
    """Construct a provider by name with explicit kwargs."""
    if name == "static":
        # StaticProvider only accepts canned_text; drop connection kwargs.
        return StaticProvider(**{k: v for k, v in kwargs.items() if k == "canned_text"})
    if name == "claude":
        from deceptinet.engine.providers.claude import ClaudeProvider

        return ClaudeProvider(**kwargs)
    if name == "ollama":
        from deceptinet.engine.providers.ollama import OllamaProvider

        return OllamaProvider(**kwargs)
    if name == "openai_compat":
        from deceptinet.engine.providers.openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(**kwargs)
    raise ValueError(f"unknown LLM provider: {name!r}")


def build_provider(name: str, llm_config) -> LLMProvider:
    """Build a provider from an :class:`~deceptinet.config.models.LLMConfig`."""
    return get_provider(
        name,
        model=llm_config.model,
        max_tokens=llm_config.max_tokens,
        temperature=llm_config.temperature,
        timeout_s=llm_config.timeout_s,
        base_url=llm_config.base_url,
        api_key=llm_config.api_key,
        api_key_env=llm_config.api_key_env,
    )
