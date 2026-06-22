# Limitations (honest, living)

Per the build spec's truthfulness mandate, this file lists what is weak,
unverified, or unimplemented. A thesis reviewer will find fabricated rigor — so
nothing here is glossed over. Items are grouped; `NOT IMPLEMENTED` means the
capability does not exist yet (it is a stub), not that it is hidden.

## A. Not implemented yet (by phase) — these are explicit stubs

- **HTTP / MySQL / POP3 services (Phase 3).** Only SSH is implemented. Enabling
  these in config emits a `NOT IMPLEMENTED` warning and the service is skipped.
- **Session classifier (Phase 4).** Every session is stored with
  `session_classification = "unknown"`. **This is the single biggest caveat for
  the research question:** until the classifier exists, engagement cannot be
  segmented into automated vs. human-like, and raw session-length comparisons
  would mostly measure bot timeout behaviour (spec §2.1). Raw timing data *is*
  being captured now (per-event timestamps, credential attempt times) so the
  classifier can run retrospectively.
- **IOC extractor & MITRE ATT&CK mapper (Phase 4).** Not implemented. Raw
  commands/credentials are captured verbatim, so no intel is lost — extraction
  is deferred, not skipped.
- **Comparison harness + statistics + figures (Phase 5).** Not implemented.
  There are **no results, no benchmark numbers, and no figures** in this repo,
  and none will be fabricated.
- **Full dashboard (Phase 6).** Only `/health` and `/stats` exist. No live
  session view / replay UI yet.
- **Reproducibility tooling / `make experiment` (Phase 7).** `make experiment`
  intentionally errors with a `NOT IMPLEMENTED` message.

## A2. LLM mode (Phase 2) — implemented, with these caveats

- **No LLM was actually called in CI.** All LLM-engine tests use a fake/in-memory
  provider or `httpx.MockTransport`; the Claude provider is tested with a fake
  SDK client. No real Claude/Ollama/OpenAI request was made in this environment.
  Response *quality* against a live model is therefore unmeasured here.
- **"Semantic" cache is whitespace-normalisation only**, NOT embedding-based
  similarity. True semantic caching (embeddings + nearest-neighbour) is **not
  implemented** — `cache.semantic: true` only collapses whitespace.
- **Prompt-injection defence is basic.** The attacker command is isolated as the
  user turn and the system prompt forbids breaking character; the output
  validator catches identity/refusal/system-prompt leaks. This has **not** been
  red-teamed against a determined jailbreaker — hardening + an explicit
  injection test corpus is Phase 7 (spec §7).
- **The output validator can false-positive.** It rejects (and falls back to
  vanilla on) any output containing strings like "claude"/"openai"/"as an AI".
  That is deliberate (ADR-015) but means some legitimate novel output is
  suppressed.
- **Latency/cost telemetry is captured but not yet analysed.** Per-event
  `latency_ms`, `cache_hit`, and token counts are stored; the RQ3 cost/latency
  analysis itself is Phase 5.
- **Pre-warming costs tokens.** When `mode: llm`, `cache.prewarm: true`, and a
  real provider is configured, the runner pre-warms a small default command set
  at boot with real LLM calls. Disable with `cache.prewarm: false`.
- **Egress vs. remote LLM:** under the default-deny Docker network, remote
  providers (Claude API) are unreachable. Use a local provider on the internal
  network (`docker-compose.llm.yml`) or run bare-metal. `allow_llm_only` egress
  is not implemented (ADR-014).

## B. Verified vs. NOT verified in this build environment

- ✅ **Application verified end-to-end without Docker.** `python -m deceptinet`
  was run as a real process; a real SSH client connected, authenticated, drove
  an interactive shell, and the full session (credentials, per-command events,
  timestamps, persisted virtual-FS state) was captured to the datastore. The
  `/health` and `/stats` endpoints responded. 80 tests pass (including the
  Phase 2 LLM engine, cache, validator, and providers — all with fakes/mocks,
  no live LLM).
- ⚠️ **`docker compose up` was NOT executed here.** The build environment's
  network policy blocks the Docker registry (Docker Hub CDN returns HTTP 403),
  so the `python:3.11-slim` base image could not be pulled and no image could be
  built. Both compose files are **schema-valid** (`docker compose config`
  passes), the Docker daemon was confirmed runnable, but the running stack and
  the **egress-lockdown behaviour were not runtime-verified in this
  environment.** Verify on a host with registry access:
  ```bash
  make up
  curl -s http://127.0.0.1:8000/health                       # ingress works
  # egress must FAIL (no route to the internet):
  docker compose exec deceptinet python -c \
    "import socket; socket.create_connection(('1.1.1.1',53),3)"
  # expected: OSError (Network is unreachable) -> egress is locked down
  ```
  If, in your Docker version, published ports do **not** reach a container on a
  pure `internal: true` network, the documented fallback is to verify ingress
  and, if needed, front the listener with a host-level reverse proxy; do not
  relax the `internal` flag (that would re-enable egress).

## C. Containment / safety caveats

- **Credentials and command content are stored in PLAINTEXT at rest.**
  Hashing/encryption at rest is Phase 7. Until then, protect the datastore at
  the OS level. (See `ETHICS.md`.)
- **`allow_llm_only` egress is not wired.** Only full `deny` is meaningfully
  enforced today. The Phase 2 LLM path will need an explicit egress
  proxy/allowlist.
- **The egress probe is a tripwire, not proof** of network isolation.
- **No automated data retention/scrubbing job** yet (manual only).

## D. SSH emulation fidelity (Phase 1)

- **Latency:** the vanilla engine responds in well under a millisecond. The LLM
  arm adds 1–8s for cache *misses*; the cache makes hits instant (spec §2.2).
  Latency injection/jitter on cached responses (`latency.inject_jitter_on_cache`)
  is **not yet implemented** — the config flag exists but is inert. Systematic
  latency-fingerprinting analysis is Phase 5.
- **Shell features:** the asyncssh line editor provides cursor movement,
  history, and backspace, but **not** shell tab-completion of filenames. There
  is no job control, no signals beyond Ctrl-C handling, and no background jobs.
- **Pipes are not interpreted:** for `a | b`, only the left command `a` runs and
  its output is returned; the event is flagged `meta.pipe_unhandled = true`.
- **Redirection is limited** to a single trailing `>`/`>>` into the virtual FS.
- **Command coverage is intentionally bounded** (see DECISIONS ADR-006):
  unknown commands return `command not found`. This is the correct, fair
  baseline behaviour — not a bug to paper over.
- **Auth:** public-key and keyboard-interactive auth are disabled to maximise
  password capture; a real OpenSSH server offers more methods. The fixed MOTD
  and `Last login` line are static.

## E. Datastore / ops

- Schema is created with `create_all`; **no Alembic migrations** yet (Phase 7).
- `event_count` on a session is denormalised and set at session close; for
  sessions that end via an abrupt transport drop it reflects events recorded
  before finalization.

## F. Known correctness scope

- The no-real-execution static scan checks for common RCE primitives
  (`subprocess`, `os.system`, `os.popen`, `os.exec*`, `pty.spawn`, ...). It is a
  strong guardrail but a static scan, not a formal proof.
