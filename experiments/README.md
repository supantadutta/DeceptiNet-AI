# experiments/

Experiment configs + run manifests. The two A/B designs (spec §5) — both
supported — and how to analyse the result.

## Design (a): parallel A/B (two stacks, same time window)

Run two stacks on two IPs/ports, one fixed to each mode, over the same window.
Pro: identical threat landscape concurrently. Con: attackers may hit both; IP
reputation can differ.

```bash
# host A (vanilla)
DECEPTINET_MODE=vanilla DECEPTINET_EXPERIMENT_ID=exp-001 \
  DECEPTINET_DATASTORE_URL=postgresql://.../deceptinet make up
# host B (llm), pointed at the SAME datastore (or merge later)
DECEPTINET_MODE=llm DECEPTINET_LLM_PROVIDER=ollama DECEPTINET_EXPERIMENT_ID=exp-001 \
  DECEPTINET_DATASTORE_URL=postgresql://.../deceptinet make up
```

Sessions are tagged with their `mode`, so the harness compares them directly.

## Design (b): time-interleaved (one endpoint, flips on a cadence)

One endpoint alternates arms over time — same IP/reputation. Con: temporal
traffic variation between windows. Enable in `config.yaml`:

```yaml
deceptinet:
  experiment:
    interleave_minutes: 60   # flip vanilla<->llm every hour
```

The runner flips `mode`, rebuilds the engine, and restarts listeners on the
cadence; each session records the mode that was active when it ran.

> Trade-offs are discussed in `METHODOLOGY.md`. Neither design removes the
> bot-vs-human confound — that's why all metrics are **segmented by
> classification** (Phase 4).

## Analyse

```bash
make experiment                       # -> paper/ (tables, figures, manifest)
python scripts/experiment.py --experiment-id exp-001
```

Interpret with `RESULTS_TEMPLATE.md`. Nothing here fabricates data — the harness
reads only real captured sessions, and reports `insufficient_data` when a segment
is too small for a valid test.

See `exp-001.example.yaml` for a documented run manifest.
