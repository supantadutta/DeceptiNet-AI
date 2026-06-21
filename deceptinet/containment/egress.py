"""Egress posture (spec §2.3).

The *authoritative* egress lockdown is enforced at the network layer by Docker
Compose (an ``internal: true`` network with no route to the internet — see
``docker-compose.yml`` and ETHICS.md). It is NOT enforced by this Python code.

What this module provides is a best-effort *runtime probe* so the health
endpoint and tests can assert "from inside this container, can I reach the
internet?" and surface a loud warning if the answer is unexpectedly "yes".

Honesty note: a passing probe is evidence, not proof. A determined attacker
inside a misconfigured network could find a path the probe didn't test. The
network-level default-deny is the real control; this is a tripwire.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class EgressProbeResult:
    reachable: bool
    target: str
    detail: str

    @property
    def locked_down(self) -> bool:
        return not self.reachable


def probe_egress(
    host: str = "1.1.1.1", port: int = 53, timeout: float = 2.0
) -> EgressProbeResult:
    """Attempt a single outbound TCP connection.

    Returns ``reachable=False`` when the connection fails (the desired, locked
    -down state). Uses a raw IP by default to avoid conflating DNS failures
    with egress success.
    """
    target = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return EgressProbeResult(True, target, "outbound TCP connection succeeded")
    except OSError as exc:
        return EgressProbeResult(False, target, f"outbound blocked: {exc.__class__.__name__}")
