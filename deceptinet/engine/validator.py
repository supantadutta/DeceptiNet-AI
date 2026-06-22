"""Output validator / leak guard for LLM responses (spec §2 / §7).

A single "I'm Claude" or "As an AI" line burns the honeypot, so this is
correctness-critical. The validator:
  1. strips markdown code fences the model may wrap output in,
  2. rejects responses that leak LLM/assistant identity, refuse, or reference
     the system prompt — signalling the engine to fall back to the vanilla
     template for that command and log the leak.

Design bias: favour false positives. A wrongly-rejected response merely falls
back to the (safe) vanilla template; a missed leak burns the honeypot. The
vanilla engine itself cannot leak — it never calls an LLM — so this is inert in
pure vanilla mode.
"""

from __future__ import annotations

import re

# Case-insensitive signals that the model broke character.
_LEAK_PATTERNS = [
    r"\bas an ai\b",
    r"\bas a language model\b",
    r"\bi am an ai\b",
    r"\bi'm an ai\b",
    r"\blanguage model\b",
    r"\bi am (just )?an? (ai|assistant|language model)\b",
    r"\bi'm (just )?an? (ai|assistant|language model)\b",
    r"\bi cannot\b",
    r"\bi can't help\b",
    r"\bi can not\b",
    r"\bi'm sorry\b",
    r"\bi am sorry\b",
    r"\bi apologi[sz]e\b",
    r"\bi'm unable\b",
    r"\bi am unable\b",
    r"\bi do not have the ability\b",
    r"\bi don't have the ability\b",
    r"\bsystem prompt\b",
    r"\bthese instructions\b",
    r"\banthropic\b",
    r"\bclaude\b",
    r"\bchatgpt\b",
    r"\bopenai\b",
    r"\bgpt-?[0-9]\b",
    r"\bas requested,? here\b",
    r"\bi'm just a\b",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _LEAK_PATTERNS]

_FENCE_RE = re.compile(r"^\s*```[^\n]*\n(.*?)\n?```\s*$", re.DOTALL)


def _strip_fences(text: str) -> str:
    m = _FENCE_RE.match(text)
    if m:
        return m.group(1)
    return text


def validate_output(text: str) -> tuple[str | None, str | None]:
    """Return ``(clean_text, None)`` if the output is safe to serve, or
    ``(None, reason)`` if it leaked and the caller should fall back.
    """
    if text is None:
        return None, "empty"
    cleaned = _strip_fences(text)
    if not cleaned.strip():
        return None, "empty"
    for pat in _COMPILED:
        if pat.search(cleaned):
            return None, f"leak:{pat.pattern}"
    return cleaned, None
