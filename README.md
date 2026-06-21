# DeceptiNet-AI

**Adaptive LLM-Based Honeypot for Threat Intelligence Collection** — a
research instrument for a controlled A/B comparison between an *adaptive
LLM-driven* honeypot and a *vanilla (static/templated)* honeypot under identical
conditions.

> ⚠️ **This is a research instrument, not a product.** Every response it
> produces is **simulated** — there is no real shell, no real filesystem
> mutation, and no real service backend. Read [`ETHICS.md`](ETHICS.md) before
> deploying anything, anywhere.

---

## Build status — Phases 0 & 1 complete

This repository currently implements **Phase 0 (scaffolding & guardrails)** and
**Phase 1 (SSH service, vanilla mode, end-to-end)**. Later phases are present
only as honest stubs that raise/inform `NOT IMPLEMENTED`.

| Capability | Status |
|---|---|
| Config layer (validated, env-overridable) | ✅ implemented |
| Structured JSON logging | ✅ implemented |
| Containment: kill switch + egress posture | ✅ implemented (egress enforced by Docker; see caveats) |
| Datastore (SQLite / Postgres) + telemetry capture | ✅ implemented |
| SSH honeypot, **vanilla** mode (banner, auth capture, PTY shell, virtual FS) | ✅ implemented |
| `LLMProvider` interface + `StaticProvider` | ✅ implemented |
| Health endpoint | ✅ implemented |
| **LLM** response engine (mode `llm`) | ⛔ Phase 2 (NOT IMPLEMENTED) |
| HTTP / MySQL / POP3 services | ⛔ Phase 3 (NOT IMPLEMENTED) |
| Session classifier / IOC / ATT&CK mapping | ⛔ Phase 4 (NOT IMPLEMENTED) |
| Comparison harness + statistics + figures | ⛔ Phase 5 (NOT IMPLEMENTED) |
| Full dashboard UI | ⛔ Phase 6 (minimal health/stats only) |

See [`LIMITATIONS.md`](LIMITATIONS.md) for the honest, detailed list (including
what was and wasn't verified in CI).

---

## Non-goals (stated up front, per spec §7)

- **Not** a real shell or real services — every response is simulated. **No real
  command execution, ever.**
- **Not** a claim to outperform LLMHoney / VelLMes on realism. The intended
  contribution is the *controlled A/B comparison* and multi-service segmented
  measurement (delivered by later phases).
- **Not** a high-interaction honeypot that runs real malware in a sandbox.
- **Not** safe to deploy on a production / corporate / university network
  without **written authorization**. See [`ETHICS.md`](ETHICS.md).
- **Not** a finished science result — it is the instrument that *collects* the
  data to answer the research questions.

---

## Quickstart

### Option A — run locally (no Docker, SQLite)

```bash
make venv          # create .venv and install deps
make run-local     # starts the SSH honeypot + health endpoint
```

By default this listens for SSH on `0.0.0.0:2222` and serves health on
`0.0.0.0:8000`, writing telemetry to `data/deceptinet.sqlite3`.

Connect to it (from another shell) — **any** password works after 2 attempts,
and `root:root` / `root:123456` / `admin:admin` are accepted immediately:

```bash
ssh -p 2222 root@127.0.0.1        # password: root
```

Inspect what was captured:

```bash
curl -s http://127.0.0.1:8000/health
python scripts/show_sessions.py --events
```

### Option B — Docker Compose (Postgres, default-deny egress)

```bash
make up            # docker compose up -d --build
curl -s http://127.0.0.1:8000/health
make logs
make down
```

Single-container (SQLite) variant:

```bash
docker compose -f docker-compose.singlecontainer.yml up -d --build
```

> **Production note:** to expose the honeypot on the real SSH port, map host
> `22 → 2222` at the Docker/host level (e.g. `ports: ["22:2222"]`). Do **not** do
> this on a network you are not authorized to instrument.

---

## Kill switch (safety control)

A single command stops all exposed listeners (spec §2.3):

```bash
make kill          # engages: touches the kill-switch file inside the container
make resume        # releases it; listeners come back within ~1s
```

Locally, the kill switch is the file at `containment.kill_switch_file`
(`/run/deceptinet.stop` by default). Create it to stop, remove it to resume.

---

## The experiment switch

The whole thesis rests on flipping **one** switch without code changes:

```yaml
deceptinet:
  mode: "vanilla"   # Phase 1: the baseline.  "llm" arrives in Phase 2.
```

`mode` and `llm.provider` are what let Phase 5 run the A/B comparison. In Phase
1, `mode: llm` is intentionally rejected by config validation so the system
never *pretends* to be the LLM it doesn't yet have.

---

## Testing

```bash
make test          # 45 tests: config, vfs, engine, providers, containment,
                   # telemetry, a no-real-execution proof, and a full SSH
                   # capture integration test.
```

---

## Repository layout

```
deceptinet/
  config/        loader + validated pydantic models
  containment/   kill switch + egress probe
  services/ssh/  asyncssh adapter (Phase 1)
  engine/        vanilla engine; providers/ (static + Phase 2 stubs); cache/validator stubs
  session/        session state, virtual filesystem, persona facts
  telemetry/      recorder (capture) + classifier/ioc/attack_map stubs (Phase 4)
  datastore/      SQLAlchemy models + engine
  dashboard/      FastAPI health/stats (Phase 6 will expand)
  analysis/       comparison harness (Phase 5 stub)
tests/            pytest suite
scripts/          show_sessions.py (read-only datastore inspector)
```

## Documentation

- [`ETHICS.md`](ETHICS.md) — ethics/legal/containment/data-retention. **Read first.**
- [`LIMITATIONS.md`](LIMITATIONS.md) — honest list of what's weak or unimplemented.
- [`DECISIONS.md`](DECISIONS.md) — architecture decision records.
- [`METHODOLOGY.md`](METHODOLOGY.md) — experiment design (populated in Phases 4–5).
- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) — how to re-run the pipeline (Phase 7).
- [`CHANGELOG.md`](CHANGELOG.md)
