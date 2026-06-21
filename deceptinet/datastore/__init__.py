"""Datastore: queryable telemetry storage (spec §3).

Postgres in Docker; SQLite fallback for laptop/CI. The schema is built to be
*analysis-ready* — every captured interaction is a row you can query, which is
what the Phase 5 comparison harness will depend on.
"""

from deceptinet.datastore.db import Datastore, make_datastore
from deceptinet.datastore.models import Base, Credential, Event, Session

__all__ = ["Datastore", "make_datastore", "Base", "Session", "Event", "Credential"]
