"""Output validator / leak guard for LLM responses.

NOT IMPLEMENTED yet (Phase 2). Its job (spec §2 / §7): strip LLM meta-leakage
("As an AI...", refusals, markdown fences, persona breaks, system-prompt
disclosure) and, on detecting a leak, fall back to the vanilla template for that
command and log the event. A single "I'm Claude" line burns the honeypot, so
this is a Phase 2 correctness-critical component. The vanilla engine cannot leak
(it never calls an LLM), so this is inert in Phase 1. See LIMITATIONS.md.
"""

__all__: list[str] = []
