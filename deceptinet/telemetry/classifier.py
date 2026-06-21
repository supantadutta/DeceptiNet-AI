"""Session classifier — NOT IMPLEMENTED (Phase 4).

Will label sessions ``automated | semi_interactive | human_like | unknown`` with
a confidence score, using inter-command timing entropy, command-sequence
predictability, interactive-feature use (tab/arrows/sudo prompts), TTY
allocation, and known-bot fingerprints (spec §2.1). This module's quality
directly determines whether RQ1 is answerable, so it gets built properly in
Phase 4 — not faked now.

Until then, every session is recorded as ``unknown`` (the honest default).
"""

from __future__ import annotations

UNKNOWN = "unknown"


def classify(*args, **kwargs):  # pragma: no cover - intentional stub
    raise NotImplementedError(
        "Session classifier is NOT IMPLEMENTED yet (Phase 4). "
        "Sessions are stored as 'unknown'. See LIMITATIONS.md / METHODOLOGY.md."
    )
