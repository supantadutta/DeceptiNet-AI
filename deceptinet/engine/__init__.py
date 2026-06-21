"""Response Engine: the swappable core (spec §3).

* Mode B — VANILLA (Phase 1): templated/canned responses, no LLM. Implemented.
* Mode A — ADAPTIVE-LLM (Phase 2): pluggable LLM provider + cache + validator.
  NOT IMPLEMENTED yet; the provider abstraction and a StaticProvider exist so
  the plumbing is exercisable with zero LLM dependency.
"""

from deceptinet.engine.base import EngineResult, ResponseEngine
from deceptinet.engine.factory import get_engine

__all__ = ["EngineResult", "ResponseEngine", "get_engine"]
