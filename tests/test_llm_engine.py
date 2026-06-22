"""Adaptive LLM engine (Phase 2): augmentation, cache, validation, fallback."""

from __future__ import annotations

import pytest

from deceptinet.engine.llm import LLMEngine
from deceptinet.engine.providers.base import LLMProvider, ProviderError, ProviderResult, PromptContext
from deceptinet.engine.providers.static import StaticProvider
from deceptinet.session.state import build_session_state

pytestmark = pytest.mark.asyncio


class FakeProvider(LLMProvider):
    def __init__(self, text: str, name: str = "fake") -> None:
        self.name = name
        self._text = text
        self.calls = 0

    async def generate(self, ctx: PromptContext) -> ProviderResult:
        self.calls += 1
        return ProviderResult(
            text=self._text, provider=self.name, model="fake-1",
            latency_ms=1.0, input_tokens=11, output_tokens=7,
        )


class BrokenProvider(LLMProvider):
    name = "broken"

    async def generate(self, ctx: PromptContext) -> ProviderResult:
        raise ProviderError("boom")


@pytest.fixture
def state():
    return build_session_state("ubuntu-22.04-webserver", "root")


async def test_known_command_stays_deterministic(state):
    eng = LLMEngine(FakeProvider("SHOULD NOT BE USED"))
    r = await eng.respond("whoami", state)
    assert r.output == "root\n"
    assert r.engine_mode == "llm"
    assert r.meta["responder"] == "template"


async def test_novel_command_uses_llm_then_caches(state):
    fp = FakeProvider("tcpdump: listening on eth0\n")
    eng = LLMEngine(fp)
    r1 = await eng.respond("tcpdump -i eth0", state)
    assert r1.meta["responder"] == "llm"
    assert r1.cache_hit is False
    assert r1.output == "tcpdump: listening on eth0\n"
    assert r1.meta["output_tokens"] == 7
    r2 = await eng.respond("tcpdump -i eth0", state)
    assert r2.cache_hit is True
    assert fp.calls == 1  # served from cache, provider not called again


async def test_leak_falls_back_to_template(state):
    eng = LLMEngine(FakeProvider("As an AI language model I cannot help."))
    r = await eng.respond("definitelynovelcmd", state)
    assert r.meta["responder"] == "template_fallback"
    assert "command not found" in r.output
    assert r.meta.get("llm_rejected", "").startswith("leak:")


async def test_static_provider_falls_back(state):
    eng = LLMEngine(StaticProvider())
    r = await eng.respond("definitelynovelcmd", state)
    assert r.meta["responder"] == "template_fallback"
    assert "command not found" in r.output


async def test_provider_error_uses_fallback_provider(state):
    fb = FakeProvider("from-fallback\n", name="fallbackfake")
    eng = LLMEngine(BrokenProvider(), fallback_provider=fb)
    r = await eng.respond("somenoveltool", state)
    assert r.meta["responder"] == "llm"
    assert r.output == "from-fallback\n"
    assert fb.calls == 1


async def test_compound_command_not_routed_to_llm(state):
    fp = FakeProvider("X\n")
    eng = LLMEngine(fp)
    r = await eng.respond("novelcmd ; echo hi", state)
    assert r.meta["responder"] == "template"
    assert fp.calls == 0  # compound lines stay with vanilla
    assert "hi" in r.output


async def test_prewarm_caches(state):
    fp = FakeProvider("warm-output\n")
    eng = LLMEngine(fp)
    n = await eng.prewarm(["exoticcmd1", "exoticcmd2"], state)
    assert n == 2
    r = await eng.respond("exoticcmd1", state)
    assert r.cache_hit is True
