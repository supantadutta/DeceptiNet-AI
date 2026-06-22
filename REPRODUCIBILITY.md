# Reproducibility

> **Status: scaffold.** Full reproducibility tooling (pinned lockfile, seed
> control, one-command `make experiment`, a clearly-labelled synthetic sample
> dataset for CI) is **Phase 7**. This file documents what is reproducible today.

## Reproduce the Phase 1 instrument today

```bash
git clone <repo> && cd DeceptiNet-AI
make venv      # creates .venv from requirements-dev.txt (pinned versions)
make test      # 45 tests should pass
make run-local # start the SSH honeypot + health endpoint (SQLite)
```

Then, in another shell, generate a captured (self-originated, benign) session
and inspect it:

```bash
ssh -p 2222 root@127.0.0.1        # password: root  -> run some commands, then exit
python scripts/show_sessions.py --events
```

## Environment

- Python 3.11+ (developed on 3.11.15).
- Dependencies pinned in `requirements.txt` / `requirements-dev.txt` and
  `pyproject.toml`. A full hash-pinned lockfile is a Phase 7 item.
- Docker / Docker Compose for the containerised path (`make up`). Note: the
  containerised path was **not** runtime-verified in the original build
  environment because its network policy blocked the image registry; see
  `LIMITATIONS.md` §B.

## Determinism notes

- The vanilla engine is deterministic given the same input and session state.
- SSH host keys are generated on first run and **persisted** (to
  `DECEPTINET_HOSTKEY_DIR`, default `data/hostkeys`) so the host fingerprint is
  stable across restarts.
- Seed control for the (future) LLM arm and any sampling is a Phase 7 item.

## Reproduce the analysis pipeline (Phase 5)

```bash
make experiment            # analyse captured sessions -> paper/ (tables, figures, manifest)
python scripts/experiment.py --db <url> --experiment-id <id>
```

`paper/manifest.json` records the provenance of each run (datastore, experiment
id, session counts per segment/mode, tool versions). On an empty/single-arm
datastore the harness reports `insufficient_data` rather than inventing numbers.

## To be written (Phase 7, do not cite as done)

- A small, clearly-labelled **synthetic** dataset for CI so the analysis
  pipeline can be exercised without real captures (the test suite already
  exercises it on controlled in-test data).
- Hash-pinned dependency lockfile.
- Seed control for the LLM arm / any sampling.
