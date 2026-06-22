"""Adaptive LLM response engine (Phase 2, Mode A).

Design (ADR-012, see DECISIONS.md): the LLM *augments* the vanilla baseline
rather than replacing it. Commands the vanilla engine already models
(``ls``/``cd``/``cat``/``mkdir``/...) stay deterministic so per-session
filesystem state remains consistent. Only the long tail of commands the vanilla
engine returns ``command not found`` for is routed to the LLM. This makes the
A/B comparison measure the *marginal* value of LLM augmentation under identical
state-keeping.

Per novel command the path is: cache lookup -> provider (with fallback) ->
output validator -> cache. Any failure (provider error, leak, empty, or no real
LLM configured) falls back to the honest vanilla ``command not found``.
"""

from __future__ import annotations

import time

from deceptinet.engine.base import EngineResult, ResponseEngine
from deceptinet.engine.cache import ResponseCache
from deceptinet.engine.prompts.ssh import build_prompt_context
from deceptinet.engine.providers.base import LLMProvider, ProviderResult
from deceptinet.engine.validator import validate_output
from deceptinet.engine.vanilla import VanillaEngine
from deceptinet.logging_setup import get_logger
from deceptinet.session.state import SessionState

_log = get_logger("deceptinet.engine.llm")

# If any of these appear we don't attempt LLM augmentation (the vanilla engine's
# sequencing/redirect handling owns these lines).
_SHELL_OPERATORS = ("|", ";", "&&", "||", ">", "<", "`", "$(")


class LLMEngine(ResponseEngine):
    mode = "llm"

    def __init__(
        self,
        provider: LLMProvider,
        *,
        vanilla: VanillaEngine | None = None,
        fallback_provider: LLMProvider | None = None,
        cache: ResponseCache | None = None,
        max_tokens: int = 600,
        temperature: float = 0.4,
        augment_only: bool = True,
    ) -> None:
        self.provider = provider
        self.fallback_provider = (
            fallback_provider if fallback_provider is not provider else None
        )
        self.vanilla = vanilla or VanillaEngine()
        self.cache = cache or ResponseCache()
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.augment_only = augment_only

    async def respond(self, command_line: str, state: SessionState) -> EngineResult:
        vanilla_result = await self.vanilla.respond(command_line, state)

        if not self._llm_eligible(command_line, vanilla_result):
            # Vanilla handled it (or it's a compound line) — keep it deterministic.
            vanilla_result.engine_mode = self.mode
            vanilla_result.meta = {**vanilla_result.meta, "responder": "template"}
            return vanilla_result

        persona = state.persona.name

        cached = self.cache.get(persona, command_line)
        if cached is not None:
            return EngineResult(
                output=cached,
                exit_status=0,
                engine_mode=self.mode,
                latency_ms=0.0,
                cache_hit=True,
                meta={"responder": "cache"},
            )

        start = time.perf_counter()
        provider_result = await self._generate(command_line, state)
        gen_ms = (time.perf_counter() - start) * 1000.0

        # No usable LLM output -> honest vanilla "command not found".
        if provider_result is None or provider_result.provider == "static":
            vanilla_result.engine_mode = self.mode
            vanilla_result.meta = {**vanilla_result.meta, "responder": "template_fallback"}
            return vanilla_result

        clean, leak = validate_output(provider_result.text)
        if clean is None:
            _log.warning(
                "llm output rejected; falling back to template",
                extra={"reason": leak, "command": command_line[:200], "event": "llm_leak"},
            )
            vanilla_result.engine_mode = self.mode
            vanilla_result.meta = {
                **vanilla_result.meta,
                "responder": "template_fallback",
                "llm_rejected": leak,
            }
            return vanilla_result

        output = clean if clean.endswith("\n") else clean + "\n"
        self.cache.put(persona, command_line, output)
        return EngineResult(
            output=output,
            exit_status=0,
            engine_mode=self.mode,
            latency_ms=provider_result.latency_ms or gen_ms,
            cache_hit=False,
            meta={
                "responder": "llm",
                "provider": provider_result.provider,
                "model": provider_result.model,
                "input_tokens": provider_result.input_tokens,
                "output_tokens": provider_result.output_tokens,
            },
        )

    # ------------------------------------------------------------------
    def _llm_eligible(self, command_line: str, vanilla_result: EngineResult) -> bool:
        if not self.augment_only:
            # Non-augment mode is reserved for future work; treat as augment.
            pass
        if not vanilla_result.meta.get("unknown_command"):
            return False
        if any(op in command_line for op in _SHELL_OPERATORS):
            return False
        return True

    async def _generate(self, command_line: str, state: SessionState) -> ProviderResult | None:
        ctx = build_prompt_context(
            command_line, state, max_tokens=self.max_tokens, temperature=self.temperature
        )
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

    async def prewarm(self, commands: list[str], state: SessionState) -> int:
        """Generate + cache responses for ``commands`` (spec §2.2 pre-warming).

        Returns the number newly cached. Makes real LLM calls — costs tokens.
        """
        warmed = 0
        for cmd in commands:
            if self.cache.get(state.persona.name, cmd) is not None:
                continue
            result = await self._generate(cmd, state)
            if result is None or result.provider == "static":
                continue
            clean, _ = validate_output(result.text)
            if clean is None:
                continue
            output = clean if clean.endswith("\n") else clean + "\n"
            self.cache.put(state.persona.name, cmd, output)
            warmed += 1
        return warmed

    async def aclose(self) -> None:
        for prov in (self.provider, self.fallback_provider):
            if prov is not None:
                await prov.aclose()


# A modest default pre-warm set (common probes). A larger list can be supplied
# by the operator; spec §2.2 suggests ~200 per service.
DEFAULT_PREWARM_COMMANDS = [
    "uname -a", "id", "w", "last", "cat /proc/cpuinfo", "lscpu", "free -m",
    "cat /etc/os-release", "ps aux", "netstat -tulpn", "ss -tulpn", "crontab -l",
    "history", "lsblk", "mount", "dmesg", "ifconfig", "ip addr", "arp -a",
    "cat /etc/shadow", "cat /root/.ssh/authorized_keys", "docker ps", "systemctl",
]
