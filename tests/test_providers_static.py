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


@pytest.mark.parametrize("name", ["claude", "ollama", "openai_compat"])
def test_phase2_providers_not_implemented(name):
    # They exist in the registry but must fail loud, not silently degrade.
    with pytest.raises(NotImplementedError):
        get_provider(name)
