"""Analysis & comparison harness — NOT IMPLEMENTED (Phase 5, the thesis core).

Will compute engagement + intelligence + cost/latency metrics per mode,
segmented by session classification, with proper significance tests
(Mann-Whitney U for heavy-tailed session-length data), effect sizes, and CIs,
and emit thesis-ready figures/tables (spec §5 Phase 5). Nothing here fabricates
numbers; it will only ever read real rows from the datastore. See
LIMITATIONS.md and (eventually) METHODOLOGY.md.
"""

__all__: list[str] = []
