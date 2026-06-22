"""LLM provider abstraction (Phase 0 deliverable)."""

from __future__ import annotations

import pytest

from deceptinet.engine.providers import StaticProvider, get_provider
from deceptinet.engine.providers.base import PromptContext


def _ctx() -> PromptContext:
    return PromptContext(
        service="ssh",
        system_prompt="you are a host",
        session_summary="cwd=/root",
        attacker_input="whoami",
    )


async def test_static_provider_returns_canned():
    p = StaticProvider()
    result = await p.generate(_ctx())
    assert result.provider == "static"
    assert result.text  # non-empty canned text
    assert result.latency_ms is not None


def test_get_provider_static():
    assert isinstance(get_provider("static"), StaticProvider)


def test_get_provider_unknown_raises():
    with pytest.raises(ValueError):
        get_provider("does-not-exist")


def test_phase2_providers_construct():
    # Phase 2: these providers are implemented. Construction must not touch the
    # network (that happens on generate()).
    from deceptinet.engine.providers.claude import ClaudeProvider
    from deceptinet.engine.providers.ollama import OllamaProvider
    from deceptinet.engine.providers.openai_compat import OpenAICompatProvider

    assert isinstance(get_provider("claude", api_key="test"), ClaudeProvider)
    assert isinstance(get_provider("ollama", base_url="http://x:11434"), OllamaProvider)
    assert isinstance(
        get_provider("openai_compat", base_url="http://x/v1"), OpenAICompatProvider
    )
