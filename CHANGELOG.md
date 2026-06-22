# Changelog

All notable changes to DeceptiNet-AI. Format loosely follows Keep a Changelog.

## [0.4.0] — Phase 4 (classification + IOC + MITRE ATT&CK intel)

### Added
- **Session classifier** (`telemetry/classifier.py`): labels sessions
  `automated | semi_interactive | human_like | unknown` with a confidence score
  from separate automation/human evidence (fingerprints, PTY allocation, timing
  entropy/pace, bot-script patterns). A definitive scanner fingerprint dominates;
  low-signal sessions are honestly `unknown`, not confidently human. Transparent
  thresholds + human-readable `reasons` on every verdict.
- **IOC extractor** (`telemetry/ioc.py`): IPv4/IPv6, URLs, domains (URL hosts +
  TLD allowlist), md5/sha1/sha256, BTC/ETH wallets, payload-download URLs, and
  credentials tried.
- **MITRE ATT&CK mapper** (`telemetry/attack_map.py`): rules table mapping
  observed behaviour to techniques (T1110, T1059, T1083, T1105, T1190, T1496, …)
  with evidence.
- **Intel report** (`analysis/intel.py`): combines the three into a structured
  JSON report per session and (optionally) persists results — classification onto
  the session, IOCs/techniques into new `iocs` / `techniques` tables. Idempotent.
- `scripts/analyze.py` CLI (`--session` / `--all`). README architecture view.

### Tests
- 102 passing (adds classifier, IOC, ATT&CK, and an end-to-end capture→analyze→
  persist intel test). All deterministic; no network.

### Notes / limitations
- Classifier thresholds are reasoned defaults, **not empirically calibrated**;
  classification runs post-hoc (not live); IOC extraction is recall-biased; the
  ATT&CK mapper is a heuristic indicator mapper. See LIMITATIONS.md §A4.

## [0.3.0] — Phase 3 (HTTP, MySQL, POP3 services — both modes)

### Added
- **HTTP honeypot** (`services/http/`): minimal HTTP/1.1, templated pages
  (index/login/admin/robots), 404 for unknown paths, full request capture
  (method/path/headers/user-agent/body) and regex tagging of SQLi / LFI /
  traversal / webshell / XSS probes. In llm mode, novel paths get generated bodies.
- **MySQL honeypot** (`services/mysql/`): real handshake, credential (username)
  capture, accept-any auth, and a `COM_QUERY` text-result-set subset (canned
  tables; llm fabricates result sets via a strict TSV contract). Explicit
  NOT IMPLEMENTED list in `protocol.py`.
- **POP3 honeypot** (`services/pop3/`): USER/PASS/STAT/LIST/RETR/TOP/UIDL/DELE/
  NOOP/RSET/CAPA/QUIT; canned mailbox (vanilla) or llm-fabricated RETR bodies.
- **Shared `LLMAugmentor`** (`engine/augment.py`): the cache → provider
  (+fallback) → leak-guard core reused by all three new services.
- `services/base.py` (`TCPHoneypot`): listener lifecycle, kill-switch gating,
  per-connection telemetry + in-flight task tracking.
- Per-service prompt builders (`engine/prompts/{http,mysql,pop3}.py`).

### Changed
- All four services are enabled by default in `config.yaml` (POP3 on `:1100`).
- Runner manages all services uniformly (start/stop/kill-switch/resume); Docker
  publishes the new ports; health endpoint lists all four as implemented.

### Tests
- 87 passing (Phase 3 adds HTTP, POP3, and MySQL — incl. a real MySQL
  handshake/auth/COM_QUERY round-trip via the wire-protocol helpers).

## [0.2.0] — Phase 2 (adaptive LLM response engine)

### Added
- **`LLMEngine`** (`mode: llm`): augments the vanilla baseline — known commands
  stay deterministic (consistent FS state), the novel long tail is routed to an
  LLM. Path: cache → provider (+ fallback) → output validator → cache, with an
  honest vanilla `command not found` fallback on any failure/leak.
- **Providers:** Claude (official `anthropic` async SDK, with a sampling-param
  guard for Opus 4.8/4.7/Fable 5), Ollama and OpenAI-compatible (`httpx`), plus
  the existing `static`. Selected by `llm.provider`; `fallback_provider` honoured.
- **Response cache** (exact + whitespace-normalised) for instant cache hits;
  optional background **pre-warming** at boot (gated, logs token cost).
- **Output validator / leak guard:** strips markdown fences, rejects
  assistant-identity / refusal / system-prompt leaks (biased to false positives).
- **Prompt builder** with persona facts + live session summary; attacker input
  isolated as untrusted data (basic prompt-injection defence).
- `docker-compose.llm.yml` override adding a local **Ollama** service on the
  `internal` network (containment-preserving LLM; no internet egress).
- `ARCHITECTURE.md`.

### Changed
- Config: `mode: llm` is now accepted (Phase-1 guard removed); added
  `llm.base_url`, `llm.api_key`, `llm.api_key_env`, `llm.augment_only`.
- Telemetry now records `engine_mode`, `cache_hit`, and LLM token counts.

### Tests
- 80 passing (Phase 2 adds LLM engine, cache, validator, prompt builder,
  provider request/parse, and an SSH-in-llm-mode integration test — all with
  fakes/mocks; no live LLM call in CI).

### Notes / limitations
- No live LLM was called in CI; "semantic" cache is normalisation-only; prompt
  -injection defence is basic (Phase 7 hardens it); remote providers are
  unreachable under default-deny egress (use local Ollama). See LIMITATIONS.md.

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
