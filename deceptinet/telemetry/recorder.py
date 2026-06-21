"""TelemetryRecorder: persist captured interactions without blocking the loop.

The honeypot runs on asyncio; the datastore is synchronous SQLAlchemy. Every
write here is dispatched to a worker thread via ``asyncio.to_thread`` so a slow
disk never stalls connection handling. Write volume is low (one row per
command), so this is more than sufficient (see DECISIONS.md).
"""

from __future__ import annotations

import asyncio
import datetime as _dt

from deceptinet.datastore.db import Datastore
from deceptinet.datastore.models import Credential, Event, Session
from deceptinet.logging_setup import get_logger

_log = get_logger("deceptinet.telemetry")

# Cap stored response size so a pathological command can't bloat a row.
_MAX_RESPONSE_CHARS = 8192


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


class TelemetryRecorder:
    def __init__(self, datastore: Datastore) -> None:
        self._ds = datastore

    async def open_session(
        self,
        *,
        experiment_id: str,
        mode: str,
        service: str,
        src_ip: str,
        src_port: int,
        client_version: str | None = None,
        term_type: str | None = None,
        meta: dict | None = None,
    ) -> "SessionHandle":
        def _create() -> str:
            with self._ds.session() as s:
                row = Session(
                    experiment_id=experiment_id,
                    mode=mode,
                    service=service,
                    src_ip=src_ip,
                    src_port=src_port,
                    client_version=client_version,
                    term_type=term_type,
                    meta=meta,
                )
                s.add(row)
                s.flush()
                return row.id

        session_id = await asyncio.to_thread(_create)
        _log.info(
            "session opened",
            extra={"session_id": session_id, "service": service, "src_ip": src_ip,
                   "mode": mode, "event": "session_open"},
        )
        return SessionHandle(self, session_id, service=service, mode=mode)

    # Low-level write helpers (run in a worker thread) ------------------
    def _write_event(self, **kwargs) -> None:
        with self._ds.session() as s:
            s.add(Event(**kwargs))

    def _write_credential(self, **kwargs) -> None:
        with self._ds.session() as s:
            s.add(Credential(**kwargs))

    def _finalize(self, session_id: str, event_count: int, meta: dict | None) -> None:
        with self._ds.session() as s:
            row = s.get(Session, session_id)
            if row is None:
                return
            row.ended_at = _utcnow()
            row.event_count = event_count
            if meta:
                merged = dict(row.meta or {})
                merged.update(meta)
                row.meta = merged

    def _patch_session(self, session_id: str, fields: dict) -> None:
        with self._ds.session() as s:
            row = s.get(Session, session_id)
            if row is None:
                return
            for k, v in fields.items():
                setattr(row, k, v)


class SessionHandle:
    """Per-session recording handle with a monotonic event sequence."""

    def __init__(
        self, recorder: TelemetryRecorder, session_id: str, *, service: str, mode: str
    ) -> None:
        self._rec = recorder
        self.session_id = session_id
        self.service = service
        self.mode = mode
        self._seq = 0
        self._closed = False

    async def record_event(
        self,
        event_type: str,
        *,
        command: str | None = None,
        response: str | None = None,
        exit_status: int | None = None,
        latency_ms: float | None = None,
        cache_hit: bool | None = None,
        engine_mode: str | None = None,
        meta: dict | None = None,
        ts: _dt.datetime | None = None,
    ) -> int:
        self._seq += 1
        seq = self._seq
        if response is not None and len(response) > _MAX_RESPONSE_CHARS:
            meta = dict(meta or {})
            meta["response_truncated"] = True
            response = response[:_MAX_RESPONSE_CHARS]
        fields = dict(
            session_id=self.session_id,
            seq=seq,
            event_type=event_type,
            command=command,
            response=response,
            exit_status=exit_status,
            latency_ms=latency_ms,
            cache_hit=cache_hit,
            engine_mode=engine_mode,
            meta=meta,
        )
        # Only override the model's auto-timestamp when a real capture time is
        # supplied (preserves inter-event timing fidelity for the Phase 4
        # classifier without writing NULL into a defaulted column).
        if ts is not None:
            fields["ts"] = ts
        await asyncio.to_thread(self._rec._write_event, **fields)
        return seq

    async def record_credential(
        self,
        username: str,
        password: str | None,
        auth_method: str,
        accepted: bool,
        ts: _dt.datetime | None = None,
    ) -> None:
        fields = dict(
            session_id=self.session_id,
            username=username,
            password=password,
            auth_method=auth_method,
            accepted=accepted,
        )
        if ts is not None:
            fields["ts"] = ts
        await asyncio.to_thread(self._rec._write_credential, **fields)

    async def patch_session(self, **fields) -> None:
        await asyncio.to_thread(self._rec._patch_session, self.session_id, fields)

    async def close(self, meta: dict | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        await asyncio.to_thread(
            self._rec._finalize, self.session_id, self._seq, meta
        )
        _log.info(
            "session closed",
            extra={"session_id": self.session_id, "events": self._seq,
                   "event": "session_close"},
        )
