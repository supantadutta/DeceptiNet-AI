"""Response Engine: the swappable core (spec §3).

* Mode B — VANILLA (Phase 1): templated/canned responses, no LLM.
* Mode A — ADAPTIVE-LLM (Phase 2): pluggable LLM provider + cache + output
  validator. Augments the vanilla baseline for novel commands (see
  ``deceptinet.engine.llm``).
"""

from deceptinet.engine.base import EngineResult, ResponseEngine
from deceptinet.engine.factory import get_engine

__all__ = ["EngineResult", "ResponseEngine", "get_engine"]
