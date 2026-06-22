"""POP3 LLM prompt builder (Phase 3).

The LLM fabricates a plausible stored email for RETR. Output is a raw RFC822
message (headers, blank line, body).
"""

from __future__ import annotations

_SYSTEM = """\
You generate the raw content of an email stored in a mailbox on a mail server.
Persona: {persona} (a small company mail host).

Output ONLY a single plausible email in RFC822 form: a few headers (From, To,
Subject, Date), then a blank line, then a short body.

Hard rules:
- Output ONLY the raw email. No markdown, no code fences, no commentary.
- Make it look like ordinary business/personal mail for mailbox user "{user}".
- NEVER mention AI or that this is generated.
"""


def build(persona: str, user: str, msg_number: int):
    system = _SYSTEM.format(persona=persona, user=user)
    attacker_input = f"Provide stored message number {msg_number} for {user}."
    cache_key = f"RETR:{user}:{msg_number}"
    return system, attacker_input, cache_key
