"""Analysis & comparison harness.

Phase 4 (implemented): per-session intelligence reports — classification, IOCs,
and MITRE ATT&CK techniques (``intel.py``).

Phase 5 (NOT IMPLEMENTED): the LLM-vs-vanilla comparison harness — engagement /
intelligence / cost metrics per mode, segmented by classification, with proper
significance tests and thesis-ready figures/tables. Nothing here fabricates
numbers; it will only ever read real rows from the datastore.
"""

from deceptinet.analysis.intel import analyze_all, analyze_session

__all__ = ["analyze_session", "analyze_all"]
