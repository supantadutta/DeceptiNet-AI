"""Per-service LLM system personas / prompt builders.

NOT IMPLEMENTED yet (Phase 2). Persona *facts* (hostname, kernel, users) live in
``deceptinet.session.personas`` and are shared with the vanilla engine so both
modes present a consistent host. The prompt builders that turn those facts +
session state into LLM system prompts will live here in Phase 2.
"""

__all__: list[str] = []
