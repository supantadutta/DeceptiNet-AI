"""SQLAlchemy ORM models for captured telemetry.

Design notes
------------
* String UUID primary keys keep the schema portable across SQLite and Postgres
  without dialect-specific UUID types.
* Timestamps are timezone-aware UTC.
* ``session_classification`` / ``classification_confidence`` exist now but are
  populated by the Phase 4 classifier; in Phase 1 they stay ``"unknown"`` /
  ``NULL``. We do NOT guess a classification we cannot yet compute.
* IOC and ATT&CK-technique tables are intentionally **not** defined yet — they
  arrive in Phase 4. Adding empty tables now would imply capability we don't
  have. See LIMITATIONS.md.
"""

from __future__ import annotations

import datetime as _dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.types import JSON


def _uuid() -> str:
    return uuid.uuid4().hex


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Session(Base):
    """One connection from a single source to a single emulated service."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    experiment_id: Mapped[str] = mapped_column(String(128), index=True)
    # The experimental switch this session ran under: "vanilla" | "llm".
    mode: Mapped[str] = mapped_column(String(16), index=True)
    service: Mapped[str] = mapped_column(String(16), index=True)  # ssh/http/mysql/pop3

    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    client_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    term_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Filled by the Phase 4 classifier. Default "unknown" (honest).
    session_classification: Mapped[str] = mapped_column(String(32), default="unknown")
    classification_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    started_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)

    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    events: Mapped[list["Event"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="Event.seq"
    )
    credentials: Mapped[list["Credential"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="Credential.ts"
    )

    @property
    def duration_s(self) -> float | None:
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()


class Credential(Base):
    """A single authentication attempt (logged whether or not it was accepted)."""

    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    ts: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    username: Mapped[str] = mapped_column(String(256))
    # Captured verbatim for threat intel. Hash-at-rest is a documented Phase 7
    # / deployment hardening item (see ETHICS.md), not yet implemented.
    password: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(32))  # password | publickey | none
    accepted: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped["Session"] = relationship(back_populates="credentials")


class Event(Base):
    """A single interaction event within a session (command, notice, etc.)."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)  # per-session monotonically increasing
    ts: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    event_type: Mapped[str] = mapped_column(String(32), index=True)
    engine_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)

    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_status: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Cost/latency telemetry (RQ3). For vanilla, latency is template-render time;
    # it becomes meaningful once the LLM engine lands in Phase 2.
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    cache_hit: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    session: Mapped["Session"] = relationship(back_populates="events")


class IOC(Base):
    """An indicator of compromise extracted from a session (Phase 4)."""

    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)  # ipv4/url/sha256/...
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Technique(Base):
    """A MITRE ATT&CK technique observed in a session (Phase 4)."""

    __tablename__ = "techniques"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)  # e.g. T1059
    name: Mapped[str] = mapped_column(String(128))
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


Index("ix_events_session_seq", Event.session_id, Event.seq)
