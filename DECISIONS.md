# Architecture Decision Records

Short ADRs for choices that a thesis reviewer (or future me) will question.
The build spec's recommended stack was followed; deviations are flagged.

## ADR-001 — Stack: Python 3.11 + asyncio (as specified)
Followed the spec: Python 3.11, asyncio throughout, `asyncssh` for SSH,
SQLAlchemy + Postgres/SQLite, FastAPI for the health/dashboard API, pluggable
`LLMProvider`. No deviation.

## ADR-002 — SQLite default locally, Postgres in Docker
The datastore URL defaults to SQLite (`sqlite:///data/deceptinet.sqlite3`) so
the system is runnable on a laptop with zero external services (spec §3 calls
for a SQLite fallback). Docker Compose overrides this with Postgres via
`DECEPTINET_DATASTORE_URL`. The schema uses portable types (string UUID PKs,
`JSON` columns) so the same models work on both.

## ADR-003 — Synchronous SQLAlchemy + `asyncio.to_thread`, not an async driver
The honeypot is async, but the datastore uses the **synchronous** SQLAlchemy
engine, with writes dispatched to a worker thread via `asyncio.to_thread`.
Rationale: telemetry write volume is low (one row per command); a synchronous
engine is far easier to audit and avoids the fragility of async DB drivers
(`asyncpg`/`aiosqlite`) and their pool/lifecycle edge cases. For a research
instrument whose *correctness* reviewers will scrutinise, auditability wins.
Revisit only if write volume becomes a measured bottleneck.

## ADR-004 — Built-in asyncssh line editor for the interactive shell
The SSH shell uses asyncssh's built-in line editor (`line_editor=True`) instead
of a hand-rolled raw-PTY reader. It correctly handles echo, backspace, and
command history out of the box, which is both more robust and more realistic.
Trade-off: it does **not** provide shell-style tab-completion of filenames
(noted in LIMITATIONS). The presence/use of interactive line-editing features is
itself a useful signal for the Phase 4 human-vs-bot classifier.

## ADR-005 — Persona facts shared between vanilla and (future) LLM modes
The "ground truth" of an emulated host (hostname, kernel, users) lives in
`deceptinet/session/personas.py` and is read by the vanilla engine now and by
the LLM engine later. This keeps both A/B arms presenting the *same* host, so
measured differences come from response *quality*, not from the two arms
accidentally claiming different facts — important for a fair comparison.

## ADR-006 — The baseline is deliberately "dumb" about novel commands
The vanilla engine returns `command not found` for commands it doesn't
template. This is intentional: handling the long tail of novel commands is
exactly the capability the LLM mode is meant to add. A baseline that faked that
capability would invalidate the experiment (spec §1). The baseline is solid for
the *common* commands a real host answers; it does not pretend beyond that.

## ADR-007 — Phase 1 rejects `mode: llm` at config-validation time
Rather than silently behaving like vanilla when `mode: llm` is set before the
LLM engine exists, config validation raises a clear error. Fail loud, never
fake. Removed in Phase 2.

## ADR-008 — Probe-only connections are still recorded
Connections that authenticate-and-leave (or fail auth and leave) without opening
a shell are finalized from the SSH `connection_lost` callback and stored with
`meta.probe_only = true`. Reconnaissance and credential-spraying are real
intelligence; dropping them would bias engagement metrics.

## ADR-009 — Egress lockdown enforced at the network layer, not in Python
Default-deny egress is a Docker `internal: true` network property, not
application code. Application code cannot reliably prevent its own outbound
connections; the network can. The Python `probe_egress()` is only a tripwire.

## ADR-010 — Container hardening: non-root, read-only rootfs, drop caps
The honeypot image runs as a non-root user with `read_only: true`,
`cap_drop: [ALL]`, `no-new-privileges`, and a tmpfs `/tmp`. The honeypot itself
must not be exploitable (spec §7). `PYTHONDONTWRITEBYTECODE=1` makes a read-only
rootfs viable; writable state is confined to the `/data` volume (host keys) and
tmpfs `/tmp` (kill-switch file).

## ADR-012 — The LLM *augments* the vanilla baseline (Phase 2)
In `llm` mode, the vanilla engine still handles every command it knows
(`ls`/`cd`/`cat`/`mkdir`/...); only commands it returns `command not found` for
are routed to the LLM. Rationale: (a) filesystem-stateful commands stay
deterministic, so per-session consistency is preserved without asking the LLM to
track FS state (which it does unreliably); (b) the A/B comparison then measures
the *marginal* intelligence the LLM adds on the novel long tail, under identical
state-keeping — a cleaner, more defensible claim than "two entirely different
systems." A pure-LLM-everything mode is noted as future work (`augment_only`
flag reserved). Documented in METHODOLOGY.md so the comparison's scope is explicit.

## ADR-013 — Claude via the official SDK; sampling-param guard
The Claude provider uses the official `anthropic` async SDK (not raw HTTP), per
Anthropic's guidance. Honeypot responses run with thinking off and small
`max_tokens` to minimise latency (a fingerprinting risk, spec §2.2). Because
`temperature`/`top_p`/`top_k` are rejected with a 400 on Opus 4.8/4.7 and Fable
5, the provider only sends `temperature` to models known to accept it (Sonnet
4.6, Opus 4.6, Haiku 4.5, older). Ollama and OpenAI-compatible providers use
`httpx` directly (no Anthropic SDK applies to them).

## ADR-014 — LLM egress vs. default-deny containment
Default-deny egress (ADR-009) means a **remote** LLM (Claude API) is unreachable
from inside the locked-down Docker stack. The containment-preserving way to run
`llm` mode is a **local** provider — Ollama or an OpenAI-compatible server — as a
container on the same `internal` network (see `docker-compose.llm.yml`); no
internet egress is needed. Running against a remote provider requires either
running outside the locked-down network (bare-metal, with the operator accepting
the egress) or a future `allow_llm_only` egress allowlist (not yet implemented).
This trade-off is documented in ETHICS.md and LIMITATIONS.md.

## ADR-015 — Output validator biases toward false positives
The leak guard rejects any LLM output matching assistant-identity / refusal /
system-prompt patterns and falls back to the vanilla template. It deliberately
over-rejects (e.g. the literal word "claude" anywhere): a false positive only
costs a (safe) vanilla fallback, whereas a missed leak burns the honeypot. This
asymmetry justifies the aggressive patterns.

## ADR-011 — Schema creation via `create_all`, not Alembic (yet)
Phase 1 uses `Base.metadata.create_all` (idempotent). Versioned Alembic
migrations are deferred to Phase 7. Acceptable because the schema is additive
and there is no production data to migrate yet. Flagged in LIMITATIONS.
