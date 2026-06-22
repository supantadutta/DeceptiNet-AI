"""Analysis & comparison harness.

* Phase 4: per-session intelligence reports — classification, IOCs, ATT&CK
  techniques (``intel.py``).
* Phase 5: the LLM-vs-vanilla comparison harness — engagement / intelligence /
  cost metrics per mode, segmented by classification, with non-parametric tests,
  effect sizes, bootstrap CIs, and thesis-ready figures/tables/manifest
  (``metrics.py`` / ``stats.py`` / ``compare.py`` / ``report.py`` / ``harness.py``).

Nothing here fabricates numbers; it only ever reads real rows from the datastore.
"""

from deceptinet.analysis.compare import compare
from deceptinet.analysis.harness import run_experiment_analysis
from deceptinet.analysis.intel import analyze_all, analyze_session
from deceptinet.analysis.metrics import collect_metrics

__all__ = [
    "analyze_session", "analyze_all", "collect_metrics", "compare",
    "run_experiment_analysis",
]
