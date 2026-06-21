"""LLM provider interface.

A provider turns a :class:`PromptContext` into a single text completion. Keeping
this interface narrow is what makes the Claude / Ollama / OpenAI-compatible /
static backends interchangeable for the A/B experiment.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass
class PromptContext:
    """Everything a provider needs to synthesise one response.

    ``attacker_input`` is UNTRUSTED. Phase 2's prompt builder must isolate it as
    data (not instructions) and the output validator must catch prompt-injection
    / persona breaks (spec §7). It is carried separately here precisely so that
    isolation is structurally enforced rather than left to string formatting.
    """

    service: str  # ssh | http | mysql | pop3
    system_prompt: str
    session_summary: str
    attacker_input: str
    max_tokens: int = 600
    temperature: float = 0.4
    extra: dict = field(default_factory=dict)


@dataclass
class ProviderResult:
    text: str
    provider: str
    model: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    meta: dict = field(default_factory=dict)


class LLMProvider(abc.ABC):
    #: stable identifier, e.g. "static" | "claude" | "ollama" | "openai_compat"
    name: str = "base"

    @abc.abstractmethod
    async def generate(self, ctx: PromptContext) -> ProviderResult:
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any held resources (HTTP clients, etc.). Default no-op."""
        return None
