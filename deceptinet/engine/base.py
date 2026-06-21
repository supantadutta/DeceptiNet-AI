"""Response engine interface shared by the vanilla and (future) LLM engines.

``respond`` is async so the Phase 2 LLM engine (network-bound) implements the
exact same contract as the vanilla engine (which simply does sync work inside
an async method). The shell loop awaits a single interface either way.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from deceptinet.session.state import SessionState


@dataclass
class EngineResult:
    """The result of handling one command line."""

    output: str
    exit_status: int = 0
    # True when the command should end the session (exit/logout/EOF).
    close_session: bool = False
    engine_mode: str = "vanilla"
    # Time spent producing the response. For vanilla this is render time; it
    # becomes the headline RQ3 latency metric once the LLM engine lands.
    latency_ms: float | None = None
    cache_hit: bool | None = None
    meta: dict = field(default_factory=dict)


class ResponseEngine(abc.ABC):
    """Produces simulated responses to attacker input. Never executes anything."""

    #: "vanilla" | "llm"
    mode: str = "vanilla"

    @abc.abstractmethod
    async def respond(self, command_line: str, state: SessionState) -> EngineResult:
        """Return a simulated response to ``command_line`` for an SSH shell.

        Implementations MUST NOT execute real commands or touch the host.
        """
        raise NotImplementedError
