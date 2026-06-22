"""Comparison harness orchestration (Phase 5, the thesis core, spec §5).

run -> ensure each session is analysed (classification/IOC/ATT&CK) -> collect
per-session metrics -> compare LLM vs vanilla per metric, segmented by
classification, with real statistics -> write CSV + LaTeX tables, distribution
figures, and a reproducibility manifest. Reads only real captured data.
"""

from __future__ import annotations

from pathlib import Path

from deceptinet.analysis.compare import compare
from deceptinet.analysis.intel import analyze_all
from deceptinet.analysis.metrics import collect_metrics
from deceptinet.analysis.report import write_csv, write_figures, write_latex, write_manifest
from deceptinet.datastore.db import Datastore
from deceptinet.logging_setup import get_logger

_log = get_logger("deceptinet.analysis.harness")


def run_experiment_analysis(
    datastore: Datastore,
    *,
    outdir: str | Path = "paper",
    experiment_id: str | None = None,
    make_figures: bool = True,
    ensure_analyzed: bool = True,
) -> dict:
    if ensure_analyzed:
        analyze_all(datastore, persist=True)

    rows = collect_metrics(datastore, experiment_id)
    comparison = compare(rows)

    out = Path(outdir)
    csv_paths = write_csv(comparison, out)
    tex_path = write_latex(comparison, out)
    manifest_path = write_manifest(
        comparison, out, datastore_url=str(datastore.engine.url), experiment_id=experiment_id
    )
    fig_paths = write_figures(rows, out) if make_figures else []

    comparison["outputs"] = {
        "csv": [str(p) for p in csv_paths],
        "latex": str(tex_path),
        "manifest": str(manifest_path),
        "figures": [str(p) for p in fig_paths],
    }
    _log.info(
        "experiment analysis complete",
        extra={"n_sessions": comparison["n_sessions"], "outdir": str(out),
               "event": "harness_done"},
    )
    return comparison
