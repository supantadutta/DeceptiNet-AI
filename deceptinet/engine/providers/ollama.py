"""Ollama (local) provider (Phase 2).

Talks to a local Ollama server over its HTTP API. Because Ollama can run as a
container on the honeypot's *internal* Docker network, this is the
containment-preserving way to run the LLM honeypot with **no internet egress**
(spec §2.3). Default endpoint ``http://localhost:11434``.
"""

from __future__ import annotations

import time

import httpx

from deceptinet.engine.providers.base import (
    LLMProvider,
    ProviderError,
    ProviderResult,
    PromptContext,
)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        *,
        model: str = "llama3",
        base_url: str | None = None,
        max_tokens: int = 600,
        temperature: float = 0.4,
        timeout_s: float = 30.0,
        **_ignored,
    ) -> None:
        self.model = model
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
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
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": ctx.attacker_input},
            ],
            "options": {
                "temperature": ctx.temperature,
                "num_predict": ctx.max_tokens or self.max_tokens,
            },
        }
        start = time.perf_counter()
        try:
            resp = await self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError(f"ollama request failed: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000.0

        text = (data.get("message") or {}).get("content", "")
        return ProviderResult(
            text=text,
            provider=self.name,
            model=self.model,
            latency_ms=latency_ms,
            input_tokens=data.get("prompt_eval_count"),
            output_tokens=data.get("eval_count"),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
