"""FastAPI app exposing a health endpoint (Phase 0/1).

Read-only by design. The only state-changing capability intentionally exposed
is the kill switch (a safety control, spec §2.3) — and it is gated behind an
explicit POST so a casual GET can never trip it.
"""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import func, select

from deceptinet import __version__
from deceptinet.config.models import Config
from deceptinet.containment.killswitch import KillSwitch
from deceptinet.datastore.db import Datastore
from deceptinet.datastore.models import Event, Session


def create_app(
    config: Config, kill_switch: KillSwitch, datastore: Datastore
) -> FastAPI:
    app = FastAPI(
        title="DeceptiNet-AI",
        version=__version__,
        description="Read-only health/telemetry API for the DeceptiNet-AI honeypot.",
    )

    @app.get("/health")
    def health() -> dict:
        enabled = [
            name
            for name, svc in {
                "ssh": config.services.ssh,
                "http": config.services.http,
                "mysql": config.services.mysql,
                "pop3": config.services.pop3,
            }.items()
            if svc.enabled
        ]
        return {
            "status": "ok",
            "version": __version__,
            "mode": config.mode,
            "experiment_id": config.experiment_id,
            "enabled_services": enabled,
            "implemented_services": ["ssh", "http", "mysql", "pop3"],
            "kill_switch_engaged": kill_switch.is_engaged(),
            "egress_policy": config.containment.egress,
        }

    @app.get("/stats")
    def stats() -> dict:
        """Lightweight counts straight from the datastore (no analysis here)."""
        with datastore.session() as s:
            sessions = s.scalar(select(func.count()).select_from(Session)) or 0
            events = s.scalar(select(func.count()).select_from(Event)) or 0
        return {"sessions": sessions, "events": events}

    return app
