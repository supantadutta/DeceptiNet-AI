# Changelog

All notable changes to DeceptiNet-AI. Format loosely follows Keep a Changelog.

## [0.1.0] — Phases 0 & 1

### Added — Phase 0 (scaffolding & guardrails)
- Validated configuration layer (pydantic v2) mirroring the spec's `config.yaml`,
  with `DECEPTINET_*` environment-variable overrides.
- Structured JSON logging (stdlib only, dependency-free).
- Containment layer: file-based **kill switch** and a best-effort **egress
  probe** tripwire. `egress: allow` is forbidden by validation.
- Datastore: SQLAlchemy 2.0 models (`sessions`, `credentials`, `events`),
  runnable on SQLite (laptop/CI) or Postgres (Docker).
- `LLMProvider` interface + `StaticProvider`; `claude`/`ollama`/`openai_compat`
  providers present as explicit `NOT IMPLEMENTED` (Phase 2) stubs.
- FastAPI health/stats endpoint; application runner orchestrating listeners,
  health server, kill-switch watcher, and graceful shutdown.
- Docker image + `docker-compose.yml` (Postgres, **default-deny egress** via an
  `internal: true` network, container hardening) and a single-container variant.
- `Makefile` (`venv`, `test`, `up`, `down`, `kill`, `resume`, `run-local`, ...).
- Docs: `README`, `ETHICS`, `DECISIONS`, `LIMITATIONS` (+ `METHODOLOGY` /
  `REPRODUCIBILITY` stubs).

### Added — Phase 1 (SSH service, vanilla mode, end-to-end)
- `asyncssh` SSH listener: realistic OpenSSH banner, credential capture, accept
  -after-N-attempts auth, PTY interactive shell (built-in line editor), and
  non-interactive exec handling.
- Session state manager + in-memory **virtual filesystem** with persisted
  within-session state (e.g. `mkdir` then `ls` shows the new directory).
- Shared **persona facts** so vanilla (and the future LLM mode) present a
  consistent host.
- **Vanilla** Cowrie-style templated response engine. Never executes real
  commands; `wget`/`curl` are captured but inert.
- **Telemetry recorder** writing structured, queryable rows off the event loop;
  probe-only connections are also captured.
- Read-only `scripts/show_sessions.py` datastore inspector.

### Tests
- 45 passing: config, virtual FS, vanilla engine, providers, kill switch,
  telemetry, a **no-real-execution** proof, and a full SSH capture integration
  test.

### Known limitations
- See `LIMITATIONS.md`. Notably: `mode: llm` and HTTP/MySQL/POP3 are not
  implemented; sessions are classified `unknown` (classifier is Phase 4); the
  comparison harness and any results are Phase 5; credentials are stored in
  plaintext (encryption is Phase 7); and `docker compose up` was not
  runtime-verified in the build environment (registry blocked).
