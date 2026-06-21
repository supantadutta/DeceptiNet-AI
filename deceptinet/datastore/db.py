"""Datastore engine/session management (SQLAlchemy 2.0, synchronous).

We use a *synchronous* engine and offload writes from the asyncio event loop via
``asyncio.to_thread`` in the telemetry recorder. Rationale (recorded in
DECISIONS.md): telemetry write volume is low, and a synchronous engine keeps the
code auditable and avoids the fragility of async DB drivers — a worthwhile trade
for a research instrument whose correctness reviewers will scrutinise.

Schema creation here uses ``create_all`` (idempotent). Alembic migrations are a
documented Phase 7 item, not yet implemented (see LIMITATIONS.md).
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from deceptinet.datastore.models import Base


class Datastore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._sessionmaker = sessionmaker(bind=engine, expire_on_commit=False)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[OrmSession]:
        """Transactional scope: commit on success, rollback on error."""
        sess = self._sessionmaker()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    def dispose(self) -> None:
        self.engine.dispose()


def make_datastore(url: str, *, echo: bool = False) -> Datastore:
    """Build a :class:`Datastore` from a SQLAlchemy URL.

    Handles the SQLite/Postgres differences so callers don't have to:
      * SQLite file URLs: ensure the parent directory exists.
      * SQLite (file or memory): allow cross-thread use (we write from a thread
        pool) and use a StaticPool for ``:memory:`` so the DB survives between
        connections within the process.
    """
    parsed = make_url(url)
    connect_args: dict = {}
    engine_kwargs: dict = {"echo": echo, "future": True}

    if parsed.get_backend_name() == "sqlite":
        connect_args["check_same_thread"] = False
        database = parsed.database or ""
        if database in ("", ":memory:"):
            # In-memory DB shared across all connections in this process.
            engine_kwargs["poolclass"] = StaticPool
        else:
            Path(database).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )

    engine = create_engine(url, connect_args=connect_args, **engine_kwargs)
    ds = Datastore(engine)
    return ds
