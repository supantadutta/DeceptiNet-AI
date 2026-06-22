# Methodology

> **Status: scaffold.** The experimental methodology is defined and completed in
> **Phases 4–5**. This file currently records only what already exists so the
> document grows honestly alongside the instrument. It does **not** yet describe
> a finished experiment, and there are no results.

## Research questions (from the build spec)

- **RQ1:** Does an adaptive LLM-based honeypot keep attackers engaged measurably
  longer than a functionally-equivalent vanilla honeypot?
- **RQ2:** Does the LLM honeypot capture richer threat intelligence per session?
- **RQ3:** What is the cost (latency, compute, $) of the LLM approach, and when
  does latency-based fingerprinting expose it?

## What is measurable today (Phases 1–3)

Captured per session across **four services** (SSH, HTTP, MySQL, POP3) in
**both** `vanilla` and `llm` modes: source IP/port, credentials attempted (with
real timestamps), and every interaction event (with per-event timestamps,
`engine_mode`, `cache_hit`, response latency, LLM token counts, and
service-specific fields — e.g. HTTP method/path/user-agent/attack-hints, SQL
queries, POP3 verbs). SSH additionally captures the client version, terminal
type, and persisted virtual-FS interactions. Sessions are stored with
`session_classification = "unknown"` until the Phase 4 classifier exists.

This is the raw substrate the later phases analyse. It is **not** yet an
experiment — there are no results.

## The A/B design decision (important, read before interpreting results)

`llm` mode **augments** the vanilla baseline rather than replacing it: commands
the vanilla engine already models stay deterministic, and only the novel
long-tail (what vanilla answers `command not found`) is routed to the LLM
(DECISIONS ADR-012). Consequently the comparison measures the **marginal**
engagement/intelligence the LLM adds *on top of* an identical baseline, under
identical filesystem state-keeping — not "two unrelated systems." This is a
deliberate scoping choice that makes the contribution defensible; a
pure-LLM-everything arm is noted as future work. Any thesis claim must be framed
as "LLM augmentation vs. template baseline," and headline metrics must still be
**segmented by session classification** (Phase 4) to avoid the bot-vs-human
confound (spec §2.1).

## Human-vs-bot classification (Phase 4 — implemented; calibration pending)

The classifier (`telemetry/classifier.py`) labels sessions
`automated | semi_interactive | human_like | unknown` with a confidence score,
from separate **automation evidence** (scanner/library fingerprints, no-PTY exec,
machine-fast or highly-regular timing, fixed bot-script patterns) and **human
evidence** (interactive PTY, human-paced or irregular timing). A definitive
scanner fingerprint is treated as conclusive; absence of signal yields `unknown`
(not a confident "human"). Every verdict carries human-readable `reasons`, and
`analysis/intel.py` writes the label/confidence back to each session.

**Calibration is pending and is the key threat to RQ1.** The weights/cutoffs are
reasoned defaults, not validated against a labelled corpus. Before citing any
RQ1 result: (a) tune thresholds against hand-labelled sessions, (b) report a
confidence distribution alongside labels, and (c) segment **all** headline
engagement metrics by classification (spec §2.1). Keystroke-level interactivity
(tab/arrow keys) is not captured — interactivity is inferred from PTY + timing.

## To be written (do not cite as done)

- **Experiment designs (Phase 5):** both (a) parallel A/B and (b)
  time-interleaved, with their trade-offs.
- **Metrics & statistics (Phase 5):** engagement, intelligence, and cost/latency
  metrics per mode and per classification; non-parametric tests (e.g.
  Mann–Whitney U) for heavy-tailed session-length distributions, effect sizes,
  and confidence intervals. **No mean will be reported without a distribution
  and a test.** Null/negative results will be reported, not buried.
