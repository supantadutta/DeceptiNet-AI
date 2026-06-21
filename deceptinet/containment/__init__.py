"""Containment layer: kill switch + egress posture (spec §2.3).

This is a *mandatory safety layer*. The honeypot must never become a pivot
point for attacking third parties, and an operator must be able to stop all
exposed listeners instantly.
"""

from deceptinet.containment.killswitch import KillSwitch
from deceptinet.containment.egress import EgressProbeResult, probe_egress

__all__ = ["KillSwitch", "EgressProbeResult", "probe_egress"]
