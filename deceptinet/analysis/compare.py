"""Compare LLM vs vanilla across metrics, segmented by session classification.

For each (segment, metric) it produces descriptive stats per mode and a
non-parametric test (vanilla as group A, llm as group B) with effect size and a
bootstrap CI. Segmentation by classification is mandatory (spec §2.1): the
``all`` segment is reported too, but headline RQ1 claims must use the
``human_like`` / ``automated`` segments.
"""

from __future__ import annotations

from deceptinet.analysis.metrics import ALL_METRICS, return_visit_rate
from deceptinet.analysis.stats import compare_groups, describe

_MODES = ("vanilla", "llm")


def _segment_rows(rows: list[dict], segment: str) -> list[dict]:
    if segment == "all":
        return rows
    return [r for r in rows if r["classification"] == segment]


def compare(rows: list[dict], metrics: list[str] | None = None) -> dict:
    metrics = metrics or ALL_METRICS
    segments = ["all"] + sorted({r["classification"] for r in rows})

    counts: dict[str, dict[str, int]] = {}
    descriptives: list[dict] = []
    tests: list[dict] = []

    for seg in segments:
        seg_rows = _segment_rows(rows, seg)
        counts[seg] = {m: sum(1 for r in seg_rows if r["mode"] == m) for m in _MODES}
        for metric in metrics:
            per_mode_values = {
                mode: [r[metric] for r in seg_rows if r["mode"] == mode]
                for mode in _MODES
            }
            for mode in _MODES:
                d = describe(per_mode_values[mode])
                descriptives.append({"segment": seg, "mode": mode, "metric": metric, **d.as_dict()})
            tests.append(
                compare_groups(metric, seg, per_mode_values["vanilla"], per_mode_values["llm"]).as_dict()
            )

    return {
        "segments": segments,
        "modes": list(_MODES),
        "metrics": metrics,
        "session_counts": counts,
        "return_visit_rate": return_visit_rate(rows),
        "descriptives": descriptives,
        "tests": tests,
        "n_sessions": len(rows),
    }
