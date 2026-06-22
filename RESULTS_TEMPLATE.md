# Results — how to read the comparison harness output

> This is a **template**, not results. It explains how to interpret the artifacts
> `make experiment` writes to `paper/`. There are **no numbers here** — they come
> from your own captured data and must never be fabricated.

The harness (`deceptinet/analysis/`) computes, for the LLM arm (B) vs the vanilla
arm (A): engagement (RQ1), intelligence (RQ2), and cost/latency (RQ3) metrics —
**per session, aggregated per mode, and segmented by session classification**.

## Artifacts in `paper/`

| File | What it is |
|---|---|
| `comparison_tests.csv` | One row per (segment, metric): group sizes, medians, Mann-Whitney U, p-value, effect size, bootstrap CI, status. |
| `comparison_descriptives.csv` | Distribution summary (n, median, mean, p95, IQR) per (segment, mode, metric). |
| `comparison_table.tex` | The same comparison as a LaTeX table for the thesis. |
| `figures/*.png` | Box-plot **distributions** (vanilla vs llm) per metric, faceted by classification. |
| `manifest.json` | Provenance: datastore, experiment id, session counts, versions. Every number traces back here. |

## Reading a test row

- **Lead with the median**, not the mean — honeypot metrics are heavy-tailed
  (a few long sessions dominate). The figures show the full distribution.
- **`p_value`** (Mann-Whitney U, two-sided): evidence that the two distributions
  differ. Pick and pre-register an α (e.g. 0.05); correct for multiple
  comparisons across the metric×segment grid (e.g. Benjamini-Hochberg).
- **`effect_size_r`** (rank-biserial): direction **and** magnitude. Sign: `+` =
  LLM tends to exceed vanilla. Magnitude: <0.1 negligible, <0.3 small, <0.5
  medium, ≥0.5 large. **A significant p with a negligible effect is not a
  finding.**
- **`ci_low`/`ci_high`**: bootstrap 95% CI for median(LLM) − median(vanilla). If
  it straddles 0, the direction is uncertain even if p is small-ish.
- **`status: insufficient_data`**: a segment had fewer than the minimum group
  size for a valid test — collect more data; do not report a number.

## Segmentation is mandatory (spec §2.1)

The honest RQ1 claim is per-segment — e.g. *"for `human_like` sessions, the LLM
arm increased median session duration by X (r=…, 95% CI …)."* The `all` segment
mixes bots and humans and will usually be dominated by automated traffic; do not
headline it. Always report the **classification confidence distribution**
alongside (the classifier thresholds are not yet calibrated — see
`LIMITATIONS.md` §A4).

## Null and negative results are real findings

If the LLM arm does **not** increase engagement (or *decreases* it) for a
segment — especially `automated` — **report that.** "Adaptive LLM responses did
not measurably change automated-bot engagement (p=…, r=…)" is a legitimate,
publishable result and must not be buried. The instrument is built to find the
truth, whichever way it points.

## Before citing anything

1. Calibrate the classifier against hand-labelled sessions (`LIMITATIONS.md` §A4).
2. Ensure adequate n per segment per mode (watch `insufficient_data`).
3. Confirm the two arms were collected under matched conditions
   (`METHODOLOGY.md`: parallel A/B vs time-interleaved).
4. Cross-check that no metric is driven by a measurement artefact (e.g. cache
   warmth, a single hyperactive source IP).
