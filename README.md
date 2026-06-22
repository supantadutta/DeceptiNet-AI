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

## Build status — Phases 0–3 complete

This repository implements **Phase 0** (scaffolding & guardrails), **Phase 1**
(SSH, vanilla), **Phase 2** (adaptive LLM response engine), and **Phase 3**
(HTTP, MySQL, POP3 — both modes). Later phases are present only as honest stubs.

| Capability | Status |
|---|---|
| Config layer (validated, env-overridable) | ✅ implemented |
| Structured JSON logging | ✅ implemented |
| Containment: kill switch + egress posture | ✅ implemented (egress enforced by Docker; see caveats) |
| Datastore (SQLite / Postgres) + telemetry capture | ✅ implemented |
| SSH honeypot (banner, auth capture, PTY shell, virtual FS) | ✅ implemented |
| HTTP honeypot (templated pages, attack-probe tagging) | ✅ Phase 3 |
| MySQL honeypot (handshake, auth capture, COM_QUERY subset) | ✅ Phase 3 |
| POP3 honeypot (USER/PASS/STAT/LIST/RETR/...) | ✅ Phase 3 |
| **LLM** response engine + cache + leak guard (all services) | ✅ Phase 2 |
| LLM providers: Claude (SDK), Ollama, OpenAI-compatible, static | ✅ Phase 2 |
| Health endpoint | ✅ implemented |
| Session classifier / IOC / ATT&CK mapping | ⛔ Phase 4 (NOT IMPLEMENTED) |
| Comparison harness + statistics + figures | ⛔ Phase 5 (NOT IMPLEMENTED) |
| Full dashboard UI | ⛔ Phase 6 (minimal health/stats only) |

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the component diagram and
[`LIMITATIONS.md`](LIMITATIONS.md) for the honest, detailed gap list (including
what was and wasn't verified in CI — notably, no live LLM was called).

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

By default this starts all four honeypot services — SSH `:2222`, HTTP `:8080`,
MySQL `:3306`, POP3 `:1100` — plus the health endpoint on `:8000`, writing
telemetry to `data/deceptinet.sqlite3`. (POP3 uses `:1100` so it binds as a
non-root user; map host `110 → 1100` in production.)

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

`mode` and `llm.provider` are what let Phase 5 run the A/B comparison.

### Enabling LLM mode (Phase 2)

In `llm` mode the LLM only handles commands the vanilla engine can't (the novel
long tail); known commands stay deterministic so session state is consistent
(see [`METHODOLOGY.md`](METHODOLOGY.md)).

```bash
# Local, containment-friendly: a local LLM on the internal network (no egress).
#   provider: ollama, base_url: http://localhost:11434
DECEPTINET_MODE=llm DECEPTINET_LLM_PROVIDER=ollama make run-local

# Claude API (requires outbound egress to api.anthropic.com — not available
# inside the default-deny Docker network; run bare-metal or use Ollama):
export ANTHROPIC_API_KEY=sk-ant-...
DECEPTINET_MODE=llm DECEPTINET_LLM_PROVIDER=claude make run-local
```

If no real provider/key is configured, `llm` mode safely degrades to the vanilla
baseline for novel commands (it never emits fake "static-provider" text to the
attacker). The output **leak guard** drops any response that breaks character
and falls back to the template.

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
