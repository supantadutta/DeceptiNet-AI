"""OpenAI-compatible endpoint provider (Phase 2).

Works with any server exposing the OpenAI chat-completions API shape — vLLM, LM
Studio, llama.cpp server, text-generation-webui, etc. ``base_url`` should point
at the API root that exposes ``/chat/completions`` (commonly ending in ``/v1``).
Like Ollama, a self-hosted endpoint on the internal network keeps egress closed.
"""

from __future__ import annotations

import os
import time

import httpx

from deceptinet.engine.providers.base import (
    LLMProvider,
    ProviderError,
    ProviderResult,
    PromptContext,
)


class OpenAICompatProvider(LLMProvider):
    name = "openai_compat"

    def __init__(
        self,
        *,
        model: str = "gpt-3.5-turbo",
        base_url: str | None = None,
        api_key: str | None = None,
        api_key_env: str | None = None,
        max_tokens: int = 600,
        temperature: float = 0.4,
        timeout_s: float = 30.0,
        **_ignored,
    ) -> None:
        self.model = model
        self.base_url = (base_url or "http://localhost:8000/v1").rstrip("/")
        if api_key is None and api_key_env:
            api_key = os.environ.get(api_key_env)
        # Many self-hosted servers ignore the key; send a placeholder if absent.
        self.api_key = api_key or "sk-no-key"
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_s = timeout_s
        self._client = httpx.AsyncClient(timeout=timeout_s)

    async def generate(self, ctx: PromptContext) -> ProviderResult:
        system = ctx.system_prompt
        if ctx.session_summary:
            system = f"{system}\n\n{ctx.session_summary}"
        payload = {
            "model": self.model,
            "max_tokens": ctx.max_tokens or self.max_tokens,
            "temperature": ctx.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": ctx.attacker_input},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        start = time.perf_counter()
        try:
            resp = await self._client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError(f"openai_compat request failed: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000.0

        choices = data.get("choices") or [{}]
        text = (choices[0].get("message") or {}).get("content", "") or ""
        usage = data.get("usage") or {}
        return ProviderResult(
            text=text,
            provider=self.name,
            model=self.model,
            latency_ms=latency_ms,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
