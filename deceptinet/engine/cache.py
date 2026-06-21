"""Response cache (exact + semantic) and pre-warming.

NOT IMPLEMENTED yet (Phase 2). This addresses the latency-fingerprinting risk
(spec §2.2): common commands should be served instantly from cache so cached and
LLM responses become timing-indistinguishable. The vanilla engine (Phase 1) is
already effectively instant, so the cache only matters once the LLM engine
exists. See LIMITATIONS.md.
"""

__all__: list[str] = []
