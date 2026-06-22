"""Reusable LLM-augmentation core shared by the HTTP/MySQL/POP3 services.

The SSH engine (``engine/llm.py``) has its own copy of this flow tuned to the
shell command/response shape; this generalised helper serves the other protocol
adapters, which have different request/response shapes (HTTP requests, SQL
queries, POP3 verbs) but the same need: cache -> provider (+fallback) -> output
validator, returning ``None`` to signal "fall back to the vanilla template".

Keeping the provider/cache/validator wiring in one place means a new service
only writes (a) a prompt builder and (b) a vanilla template responder.
"""

from __future__ import annotations

from deceptinet.engine.cache import ResponseCache
from deceptinet.engine.providers.base import LLMProvider, PromptContext, ProviderResult
from deceptinet.engine.validator import validate_output
from deceptinet.logging_setup import get_logger

_log = get_logger("deceptinet.engine.augment")


class LLMAugmentor:
    def __init__(
        self,
        provider: LLMProvider,
        *,
        fallback_provider: LLMProvider | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self.provider = provider
        self.fallback_provider = (
            fallback_provider if fallback_provider is not provider else None
        )
        self.cache = cache or ResponseCache()

    async def generate(
        self,
        *,
        service: str,
        persona: str,
        cache_key: str,
        system_prompt: str,
        session_summary: str,
        attacker_input: str,
        max_tokens: int = 600,
        temperature: float = 0.4,
    ) -> tuple[str | None, dict]:
        """Return ``(text, meta)``. ``text is None`` => caller uses the vanilla
        template. ``meta`` always carries a ``responder`` key for telemetry."""
        cached = self.cache.get(persona, cache_key)
        if cached is not None:
            return cached, {"responder": "cache", "cache_hit": True}

        ctx = PromptContext(
            service=service,
            system_prompt=system_prompt,
            session_summary=session_summary,
            attacker_input=attacker_input,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        result = await self._gen(ctx)
        if result is None or result.provider == "static":
            return None, {"responder": "template_fallback"}

        clean, leak = validate_output(result.text)
        if clean is None:
            _log.warning(
                "llm output rejected; falling back to template",
                extra={"reason": leak, "service": service, "event": "llm_leak"},
            )
            return None, {"responder": "template_fallback", "llm_rejected": leak}

        self.cache.put(persona, cache_key, clean)
        return clean, {
            "responder": "llm",
            "provider": result.provider,
            "model": result.model,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "latency_ms": result.latency_ms,
            "cache_hit": False,
        }

    async def _gen(self, ctx: PromptContext) -> ProviderResult | None:
        for prov in (self.provider, self.fallback_provider):
            if prov is None:
                continue
            try:
                return await prov.generate(ctx)
            except Exception as exc:  # never let an LLM error crash the honeypot
                _log.warning(
                    "provider failed",
                    extra={"provider": prov.name, "error": str(exc)[:200],
                           "event": "llm_provider_error"},
                )
                continue
        return None

    async def aclose(self) -> None:
        for prov in (self.provider, self.fallback_provider):
            if prov is not None:
                await prov.aclose()
