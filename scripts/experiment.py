#!/usr/bin/env python3
"""Run the LLM-vs-vanilla comparison harness (Phase 5).

Usage:
    python scripts/experiment.py [--db URL] [--experiment-id ID]
                                 [--outdir paper] [--no-figures]

Analyses every captured session (classification + IOC + ATT&CK), computes
engagement / intelligence / cost metrics per mode segmented by classification,
runs non-parametric tests, and writes CSV + LaTeX tables, distribution figures,
and a reproducibility manifest. Reads only real captured data — fabricates
nothing. If there is no data, it says so.
"""

from __future__ import annotations

import argparse
import sys

sys.path.insert(0, ".")

from deceptinet.analysis.harness import run_experiment_analysis  # noqa: E402
from deceptinet.analysis.stats import effect_label  # noqa: E402
from deceptinet.config.loader import load_config  # noqa: E402
from deceptinet.datastore.db import make_datastore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", help="datastore URL (default: from config.yaml)")
    ap.add_argument("--config", default=None)
    ap.add_argument("--experiment-id", default=None)
    ap.add_argument("--outdir", default="paper")
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args()

    url = args.db or load_config(args.config).datastore.url
    ds = make_datastore(url)
    ds.create_all()
    comp = run_experiment_analysis(
        ds, outdir=args.outdir, experiment_id=args.experiment_id,
        make_figures=not args.no_figures,
    )
    ds.dispose()

    print(f"\nDeceptiNet-AI comparison harness — {comp['n_sessions']} session(s)")
    if comp["n_sessions"] == 0:
        print("No captured sessions found. Collect data first (run the honeypot),")
        print("then re-run. Nothing was fabricated.")
        return 0

    print("session counts (segment -> {vanilla, llm}):")
    for seg, c in comp["session_counts"].items():
        print(f"  {seg:<16} {c}")
    print("\nLLM (B) vs vanilla (A) — median_A -> median_B, p, effect:")
    for t in comp["tests"]:
        if t["status"] != "ok":
            print(f"  [{t['segment']:<14}] {t['metric']:<20} {t['status']}")
            continue
        print(
            f"  [{t['segment']:<14}] {t['metric']:<20} "
            f"{t['median_a']:.2f} -> {t['median_b']:.2f}  "
            f"p={t['p_value']:.3g}  r={t['effect_size_r']:+.2f} ({effect_label(t['effect_size_r'])})"
        )
    print("\noutputs:")
    for k, v in comp["outputs"].items():
        print(f"  {k}: {v}")
    print("\nInterpret these with paper/../RESULTS_TEMPLATE.md. "
          "'insufficient_data' = too few sessions for a valid test (collect more).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
