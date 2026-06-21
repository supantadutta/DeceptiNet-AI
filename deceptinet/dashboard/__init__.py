"""Read-only dashboard + health/metrics API (spec §3, Phase 6).

Phase 0/1 ships only a health endpoint (enough to satisfy "health endpoint
responds"). The live-sessions UI, per-session replay, and live LLM-vs-vanilla
metrics are Phase 6. See LIMITATIONS.md.
"""

from deceptinet.dashboard.app import create_app

__all__ = ["create_app"]
