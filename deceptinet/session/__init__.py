"""Session state management: per-session virtual filesystem + shell state.

Consistency is the whole point: if an attacker runs ``mkdir x``, a later ``ls``
must show ``x``. The vanilla engine (Phase 1) maintains this with a real
in-memory structure; the LLM engine (Phase 2) will additionally feed a compact
summary of this state into prompts so generated responses stay consistent.
"""

from deceptinet.session.state import SessionState
from deceptinet.session.vfs import VirtualFS, VfsError

__all__ = ["SessionState", "VirtualFS", "VfsError"]
