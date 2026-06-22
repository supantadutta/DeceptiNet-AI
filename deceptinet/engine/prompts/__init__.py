"""Per-service LLM system personas / prompt builders (Phase 2).

Persona *facts* (hostname, kernel, users) live in
``deceptinet.session.personas`` and are shared with the vanilla engine so both
modes present a consistent host. The builders here turn those facts + live
session state into LLM prompts, isolating untrusted attacker input as data.

Phase 1 = SSH. HTTP/MySQL/POP3 prompt builders arrive in Phase 3.
"""

from deceptinet.engine.prompts.ssh import (
    build_prompt_context,
    build_session_summary,
    build_system_prompt,
)

__all__ = ["build_prompt_context", "build_session_summary", "build_system_prompt"]
