"""Claude API provider (Phase 2) — uses the official Anthropic async SDK.

Honeypot responses must be fast and short to limit latency-fingerprinting
(spec §2.2), so we run with thinking OFF and a small ``max_tokens``.

Model-compatibility note: ``temperature`` (and other sampling params) are
rejected with a 400 on Opus 4.8/4.7 and Fable 5. We therefore only send
``temperature`` to models known to accept it.
"""

from __future__ import annotations

import os
import time

from deceptinet.engine.providers.base import (
    LLMProvider,
    ProviderError,
    ProviderResult,
    PromptContext,
)
from deceptinet.logging_setup import get_logger

_log = get_logger("deceptinet.provider.claude")

# Model-ID prefixes that REJECT temperature/top_p/top_k (send none).
_NO_SAMPLING_PREFIXES = (
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-fable-5",
    "claude-mythos-5",
)


def _supports_sampling(model: str) -> bool:
    return not any(model.startswith(p) for p in _NO_SAMPLING_PREFIXES)


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 600,
        temperature: float = 0.4,
        timeout_s: float = 8.0,
        api_key: str | None = None,
        api_key_env: str | None = None,
        **_ignored,
    ) -> None:
        # Imported lazily so the package imports even if the SDK isn't installed.
        from anthropic import AsyncAnthropic

        if api_key is None and api_key_env:
            api_key = os.environ.get(api_key_env)
        # If api_key is still None the SDK reads ANTHROPIC_API_KEY from the env.
        self._client = AsyncAnthropic(api_key=api_key) if api_key else AsyncAnthropic()
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_s = timeout_s

    async def generate(self, ctx: PromptContext) -> ProviderResult:
        from anthropic import APIError, APITimeoutError

        system = ctx.system_prompt
        if ctx.session_summary:
            system = f"{system}\n\n{ctx.session_summary}"

        kwargs: dict = {
            "model": self.model,
            "max_tokens": ctx.max_tokens or self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": ctx.attacker_input}],
        }
        if _supports_sampling(self.model):
            kwargs["temperature"] = ctx.temperature

        start = time.perf_counter()
        try:
            resp = await self._client.with_options(timeout=self.timeout_s).messages.create(
                **kwargs
            )
        except (APITimeoutError, APIError) as exc:
            # Surface as a provider failure so the engine can fall back.
            raise ProviderError(str(exc)) from exc
        latency_ms = (time.perf_counter() - start) * 1000.0

        # A safety refusal returns an empty/partial body; treat as no answer.
        if getattr(resp, "stop_reason", None) == "refusal":
            _log.warning("claude refusal", extra={"event": "llm_refusal"})
            return ProviderResult(
                text="", provider=self.name, model=self.model,
                latency_ms=latency_ms, meta={"refusal": True},
            )

        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        usage = getattr(resp, "usage", None)
        return ProviderResult(
            text=text,
            provider=self.name,
            model=self.model,
            latency_ms=latency_ms,
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
        )

    async def aclose(self) -> None:
        await self._client.close()
