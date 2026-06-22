# DeceptiNet-AI — Architecture

This document describes how the system is built and how a request flows through
it. It reflects the **current implementation** (Phases 0–2). Components that are
later-phase stubs are marked accordingly so the diagram never overstates what
exists. See `LIMITATIONS.md` for the honest gap list.

## 1. High-level diagram

```
   Attacker / scanner
          │  SSH :2222   HTTP :8080   MySQL :3306   POP3 :1100
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Exposure + Protocol Emulation Layer            deceptinet/services/       │
│  • SSH (asyncssh): banner, persisted host keys, credential capture, PTY   │
│    shell (line editor) + exec path                                        │
│  • HTTP: minimal HTTP/1.1, templated pages, attack-probe tagging          │
│  • MySQL: handshake + auth capture + COM_QUERY result-set subset          │
│  • POP3: USER/PASS/STAT/LIST/RETR/... + credential capture                │
│  • all parse attacker input into events — NEVER execute anything          │
└─────────────────────────────────────────────────────────────────────────┘
          │  command line + SessionState
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Response Engine (the swappable core)                   deceptinet/engine/ │
│                                                                           │
│  mode: "vanilla"  ──────────────►  VanillaEngine (templated, Cowrie-style)│
│                                     deterministic; owns FS-stateful cmds  │
│                                                                           │
│  mode: "llm"      ──►  LLMEngine (augments vanilla for NOVEL commands):   │
│        1. VanillaEngine handles known cmds (ls/cd/cat/mkdir…) → consistent │
│        2. unknown cmd → cache lookup (exact + whitespace-normalised)      │
│        3. miss → LLMProvider.generate(prompt)   [claude|ollama|openai|…]  │
│        4. output validator / leak guard  →  cache  →  serve               │
│        5. any failure/leak/no-LLM → honest vanilla "command not found"    │
└─────────────────────────────────────────────────────────────────────────┘
          │  EngineResult (output, latency, tokens, cache_hit, meta)
          ▼
┌──────────────────────────┐   ┌──────────────────────────────────────────┐
│ Session State Manager     │   │ Telemetry & Capture                        │
│ deceptinet/session/       │   │ deceptinet/telemetry/                      │
│  • virtual filesystem      │   │  • every interaction → structured row      │
│    (in-memory, consistent) │   │    (off the event loop via to_thread)      │
│  • cwd, env, fake users    │   │  • classifier / IOC / ATT&CK → Phase 4 stub│
│  • shared persona facts ───┼───┘                                            │
└──────────────────────────┘                  │                              │
                                               ▼                              │
                              ┌──────────────────────────────────────────────┐
                              │ Datastore   deceptinet/datastore/             │
                              │  SQLAlchemy: sessions / credentials / events  │
                              │  SQLite (laptop/CI) | Postgres (Docker)       │
                              └──────────────────────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────────────────┐
                              │ Dashboard / API   deceptinet/dashboard/       │
                              │  /health, /stats  (full UI → Phase 6)         │
                              │ Analysis harness  deceptinet/analysis/ Phase 5│
                              └──────────────────────────────────────────────┘

 Containment layer (deceptinet/containment/) wraps everything:
   • kill switch (file-based) → runner stops/resumes all listeners
   • egress: enforced by Docker `internal: true` network (default-deny)
 Config layer (deceptinet/config/) is the single source of truth (config.yaml).
```

## 2. Component status

| Layer | Module | Status |
|---|---|---|
| Config (validated, env-overridable) | `config/` | ✅ |
| Logging (structured JSON) | `logging_setup.py` | ✅ |
| Containment (kill switch, egress probe) | `containment/` | ✅ |
| SSH protocol adapter | `services/ssh/` | ✅ |
| HTTP / MySQL / POP3 adapters | `services/{http,mysql,pop3}/`, `services/base.py` | ✅ Phase 3 |
| Vanilla engine (SSH) | `engine/vanilla.py` | ✅ |
| LLM engine (SSH) + shared augmentor (HTTP/MySQL/POP3) | `engine/llm.py`, `augment.py`, `cache.py`, `validator.py`, `providers/`, `prompts/` | ✅ Phase 2–3 |
| Session state + virtual FS + personas | `session/` | ✅ |
| Telemetry recorder | `telemetry/recorder.py` | ✅ |
| Classifier / IOC / ATT&CK mapper | `telemetry/{classifier,ioc,attack_map}.py` | ✅ Phase 4 |
| Intel report (classification + IOC + ATT&CK) | `analysis/intel.py` | ✅ Phase 4 |
| Datastore (models + engine; +iocs/techniques) | `datastore/` | ✅ |
| Dashboard (health/stats) | `dashboard/` | ✅ minimal (full UI Phase 6) |
| Comparison harness + stats + figures | `analysis/` | ⛔ Phase 5 |
| Runner / process orchestration | `runner.py`, `__main__.py` | ✅ |

## 3. Request lifecycle (SSH, one command)

1. **Connection** → `services/ssh/server.py` records peer; refuses if the kill
   switch is engaged.
2. **Auth** → every `validate_password` attempt is captured (username, password,
   timestamp, accepted?). Access is granted after N attempts or on a configured
   weak credential.
3. **Shell** → the PTY line editor reads a command line. A `SessionState`
   (persona-seeded virtual FS, cwd, env) is created on first shell/exec.
4. **Engine** → `engine.respond(command_line, state)`:
   - **vanilla mode:** templated handler (or `command not found`). FS mutations
     update the in-memory VFS so later commands stay consistent.
   - **llm mode:** vanilla first; if the command is unknown and simple, try the
     cache, then the LLM provider (with fallback), then the output validator;
     serve the validated text or fall back to the vanilla template.
5. **Telemetry** → the command, response (truncated), exit status, latency,
   cache-hit flag, engine mode, and token counts are written to the datastore as
   an `Event` (timestamped at capture time) without blocking the event loop.
6. **Session close** → `ended_at`, `event_count` are finalized. Probe-only
   connections (failed auth, no shell) are still recorded.

## 4. The A/B switch

`config.mode` (`vanilla` | `llm`) and `llm.provider` are the only switches
needed to run the thesis comparison. Both arms share the **same** persona facts,
virtual FS, telemetry schema, and SSH front door, so measured differences come
from response *quality*, not incidental setup differences. The LLM arm augments
the vanilla baseline (it does not replace it) — see DECISIONS ADR-012 and
METHODOLOGY.md for why this is the cleaner, more defensible comparison.

## 5. Containment & data flow safety

- **No real execution path exists** — proven by `tests/test_no_real_execution.py`
  (behavioural + static source scan). Every response is synthesised.
- **Egress** is default-deny at the Docker network layer. Remote LLM providers
  (Claude API) therefore can't be reached from inside the locked-down stack; the
  containment-preserving way to run llm mode is a **local** provider (Ollama /
  an OpenAI-compatible server) on the same `internal` network — see
  `docker-compose.llm.yml`. See ETHICS.md / LIMITATIONS.md.
- **Untrusted attacker input** is carried into LLM prompts as data (the user
  turn), never as instructions; the output validator catches persona breaks.
