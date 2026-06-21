"""Engine factory: pick the response engine from config (the A/B switch)."""

from __future__ import annotations

from deceptinet.config.models import Config
from deceptinet.engine.base import ResponseEngine
from deceptinet.engine.vanilla import VanillaEngine


def get_engine(config: Config) -> ResponseEngine:
    """Return the response engine for the configured mode.

    Phase 1 implements ``vanilla`` only. ``llm`` is rejected earlier by config
    validation, but we fail loud here too in case the engine is constructed
    directly.
    """
    if config.mode == "vanilla":
        return VanillaEngine()
    raise NotImplementedError(
        "LLM response engine is NOT IMPLEMENTED yet (Phase 2). "
        "Set mode: 'vanilla'. See LIMITATIONS.md."
    )
