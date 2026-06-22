"""Statistics for the comparison harness (Phase 5, spec §5).

Honeypot metrics are heavy-tailed, so we lead with medians + a non-parametric
test (Mann-Whitney U), an effect size (rank-biserial correlation), and a
bootstrap CI for the difference in medians — never a bare mean. Tests require a
minimum group size; below it the result is marked ``insufficient_data`` rather
than reporting a misleading number.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy import stats

MIN_GROUP_N = 5  # below this, don't run the test


@dataclass
class Description:
    n: int
    median: float | None
    mean: float | None
    p95: float | None
    iqr: float | None

    def as_dict(self) -> dict:
        return {"n": self.n, "median": self.median, "mean": self.mean,
                "p95": self.p95, "iqr": self.iqr}


@dataclass
class TestResult:
    metric: str
    segment: str
    n_a: int           # group A (e.g. vanilla)
    n_b: int           # group B (e.g. llm)
    median_a: float | None
    median_b: float | None
    u_statistic: float | None
    p_value: float | None
    effect_size_r: float | None   # rank-biserial; sign: + => B > A
    ci_low: float | None          # bootstrap 95% CI for median(B) - median(A)
    ci_high: float | None
    status: str                   # "ok" | "insufficient_data"

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def describe(values: list[float]) -> Description:
    if not values:
        return Description(0, None, None, None, None)
    arr = np.asarray(values, dtype=float)
    q1, q3 = np.percentile(arr, [25, 75])
    return Description(
        n=len(arr),
        median=float(np.median(arr)),
        mean=float(np.mean(arr)),
        p95=float(np.percentile(arr, 95)),
        iqr=float(q3 - q1),
    )


def _bootstrap_median_diff_ci(
    a: np.ndarray, b: np.ndarray, *, n_boot: int = 2000, seed: int = 1234
) -> tuple[float | None, float | None]:
    if len(a) < MIN_GROUP_N or len(b) < MIN_GROUP_N:
        return None, None
    rng = np.random.default_rng(seed)
    diffs = np.empty(n_boot)
    for i in range(n_boot):
        ra = rng.choice(a, size=len(a), replace=True)
        rb = rng.choice(b, size=len(b), replace=True)
        diffs[i] = np.median(rb) - np.median(ra)
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    return float(lo), float(hi)


def compare_groups(metric: str, segment: str, group_a: list[float], group_b: list[float]) -> TestResult:
    """Compare group_b (e.g. llm) against group_a (e.g. vanilla)."""
    a = np.asarray(group_a, dtype=float)
    b = np.asarray(group_b, dtype=float)
    med_a = float(np.median(a)) if len(a) else None
    med_b = float(np.median(b)) if len(b) else None

    if len(a) < MIN_GROUP_N or len(b) < MIN_GROUP_N:
        return TestResult(metric, segment, len(a), len(b), med_a, med_b,
                          None, None, None, None, None, "insufficient_data")

    # Mann-Whitney U (two-sided). scipy returns U for the first argument (A).
    u_a, p = stats.mannwhitneyu(a, b, alternative="two-sided")
    # Rank-biserial effect size oriented so positive => B tends to exceed A:
    #   r = 2*U_b/(n_a*n_b) - 1 = 1 - 2*U_a/(n_a*n_b)
    r = 1.0 - (2.0 * u_a) / (len(a) * len(b))
    lo, hi = _bootstrap_median_diff_ci(a, b)

    return TestResult(
        metric, segment, len(a), len(b), med_a, med_b,
        float(u_a), float(p), float(r), lo, hi, "ok",
    )


def effect_label(r: float | None) -> str:
    if r is None:
        return "n/a"
    a = abs(r)
    if a < 0.1:
        return "negligible"
    if a < 0.3:
        return "small"
    if a < 0.5:
        return "medium"
    return "large"
