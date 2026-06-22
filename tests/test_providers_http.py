"""Provider request-building + response-parsing (no network).

Ollama / OpenAI-compatible providers are exercised with httpx.MockTransport so
the real request construction and parsing run. The Claude provider is exercised
with a fake SDK client so we verify response parsing and the sampling-parameter
guard (temperature must NOT be sent to models that reject it).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from deceptinet.engine.providers.base import PromptContext
from deceptinet.engine.providers.claude import ClaudeProvider, _supports_sampling
from deceptinet.engine.providers.ollama import OllamaProvider
from deceptinet.engine.providers.openai_compat import OpenAICompatProvider


def _ctx(cmd="tcpdump -i eth0") -> PromptContext:
    return PromptContext(
        service="ssh", system_prompt="SYS", session_summary="STATE",
        attacker_input=cmd, max_tokens=128, temperature=0.4,
    )


async def test_ollama_request_and_parse():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"message": {"content": "ok-output\n"}, "eval_count": 4, "prompt_eval_count": 9}
        )

    prov = OllamaProvider(model="llama3", base_url="http://ollama:11434")
    prov._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await prov.generate(_ctx())
    await prov.aclose()

    assert captured["url"].endswith("/api/chat")
    roles = [m["role"] for m in captured["body"]["messages"]]
    assert roles == ["system", "user"]
    assert captured["body"]["messages"][1]["content"] == "tcpdump -i eth0"
    assert result.text == "ok-output\n"
    assert result.output_tokens == 4
    assert result.provider == "ollama"


async def test_openai_compat_request_and_parse():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hello\n"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )

    prov = OpenAICompatProvider(model="m", base_url="http://vllm:8000/v1", api_key="k")
    prov._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await prov.generate(_ctx())
    await prov.aclose()

    assert captured["url"].endswith("/chat/completions")
    assert captured["auth"] == "Bearer k"
    assert result.text == "hello\n"
    assert result.input_tokens == 5


def test_claude_sampling_guard():
    # Models that reject sampling params:
    assert _supports_sampling("claude-opus-4-8") is False
    assert _supports_sampling("claude-opus-4-7") is False
    assert _supports_sampling("claude-fable-5") is False
    # Models that accept them:
    assert _supports_sampling("claude-sonnet-4-6") is True
    assert _supports_sampling("claude-haiku-4-5") is True


class _FakeMessages:
    def __init__(self, sink):
        self._sink = sink

    async def create(self, **kwargs):
        self._sink.update(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text="claude-out\n")],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=3, output_tokens=2),
        )


class _FakeClient:
    def __init__(self, sink):
        self.messages = _FakeMessages(sink)

    def with_options(self, **_):
        return self


async def test_claude_omits_temperature_for_opus():
    sink: dict = {}
    prov = ClaudeProvider(model="claude-opus-4-8", api_key="test")
    prov._client = _FakeClient(sink)
    result = await prov.generate(_ctx())
    assert "temperature" not in sink           # guarded: opus rejects it
    assert sink["model"] == "claude-opus-4-8"
    assert sink["messages"][0]["content"] == "tcpdump -i eth0"
    assert result.text == "claude-out\n"
    assert result.input_tokens == 3


async def test_claude_sends_temperature_for_sonnet():
    sink: dict = {}
    prov = ClaudeProvider(model="claude-sonnet-4-6", api_key="test")
    prov._client = _FakeClient(sink)
    await prov.generate(_ctx())
    assert sink["temperature"] == 0.4


async def test_claude_refusal_returns_empty():
    prov = ClaudeProvider(model="claude-sonnet-4-6", api_key="test")

    class _Refuse:
        def with_options(self, **_):
            return self

        class messages:  # noqa: N801
            @staticmethod
            async def create(**kwargs):
                return SimpleNamespace(content=[], stop_reason="refusal", usage=None)

    prov._client = _Refuse()
    result = await prov.generate(_ctx())
    assert result.text == ""
    assert result.meta.get("refusal") is True
