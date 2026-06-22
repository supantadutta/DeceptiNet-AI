"""Engine factory: pick the response engine from config (the A/B switch)."""

from __future__ import annotations

from deceptinet.config.models import Config
from deceptinet.engine.base import ResponseEngine
from deceptinet.engine.cache import ResponseCache
from deceptinet.engine.vanilla import VanillaEngine


def get_engine(
    config: Config,
    *,
    provider=None,
    fallback_provider=None,
) -> ResponseEngine:
    """Return the response engine for the configured mode (``vanilla`` | ``llm``).

    ``provider`` / ``fallback_provider`` may be injected (used by tests) to avoid
    constructing real network providers.
    """
    if config.mode == "vanilla":
        return VanillaEngine()

    if config.mode == "llm":
        # Imported here so vanilla mode never imports provider/LLM machinery.
        from deceptinet.engine.llm import LLMEngine
        from deceptinet.engine.providers import build_provider

        if provider is None:
            provider = build_provider(config.llm.provider, config.llm)
        if fallback_provider is None and config.llm.fallback_provider != config.llm.provider:
            fallback_provider = build_provider(config.llm.fallback_provider, config.llm)

        return LLMEngine(
            provider,
            fallback_provider=fallback_provider,
            cache=ResponseCache(
                enabled=config.cache.enabled, semantic=config.cache.semantic
            ),
            max_tokens=config.llm.max_tokens,
            temperature=config.llm.temperature,
            augment_only=config.llm.augment_only,
        )

    raise ValueError(f"unknown mode: {config.mode!r}")


def build_augmentor(config: Config, *, provider=None, fallback_provider=None):
    """Build a shared :class:`~deceptinet.engine.augment.LLMAugmentor` for the
    HTTP/MySQL/POP3 services, or ``None`` in vanilla mode.

    ``provider`` may be injected by tests to avoid real network providers.
    """
    if config.mode != "llm":
        return None
    from deceptinet.engine.augment import LLMAugmentor
    from deceptinet.engine.providers import build_provider

    if provider is None:
        provider = build_provider(config.llm.provider, config.llm)
    if fallback_provider is None and config.llm.fallback_provider != config.llm.provider:
        fallback_provider = build_provider(config.llm.fallback_provider, config.llm)
    return LLMAugmentor(
        provider,
        fallback_provider=fallback_provider,
        cache=ResponseCache(enabled=config.cache.enabled, semantic=config.cache.semantic),
    )
