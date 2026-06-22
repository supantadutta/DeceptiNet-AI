"""Shared asyncio TCP honeypot base for the HTTP/MySQL/POP3 adapters.

Handles the listener lifecycle, kill-switch gating, and per-connection telemetry
session bookkeeping so each protocol adapter only implements ``_handle``.
NEVER executes anything — adapters synthesise every response.
"""

from __future__ import annotations

import asyncio

from deceptinet.config.models import Config
from deceptinet.containment.killswitch import KillSwitch
from deceptinet.engine.augment import LLMAugmentor
from deceptinet.logging_setup import get_logger
from deceptinet.telemetry.recorder import SessionHandle, TelemetryRecorder


class TCPHoneypot:
    #: one of "http" | "mysql" | "pop3" — also the config.services key.
    service_name: str = "tcp"

    def __init__(
        self,
        config: Config,
        recorder: TelemetryRecorder,
        kill_switch: KillSwitch,
        *,
        augmentor: LLMAugmentor | None = None,
    ) -> None:
        self.config = config
        self.recorder = recorder
        self.kill_switch = kill_switch
        self.augmentor = augmentor
        self._log = get_logger(f"deceptinet.{self.service_name}")
        self._server: asyncio.AbstractServer | None = None
        self._bg: set[asyncio.Task] = set()

    @property
    def _svc_config(self):
        return getattr(self.config.services, self.service_name)

    @property
    def persona(self) -> str:
        return self._svc_config.persona

    @property
    def bound_port(self) -> int | None:
        if self._server is None:
            return None
        socks = self._server.sockets
        return socks[0].getsockname()[1] if socks else None

    async def start(self) -> None:
        svc = self._svc_config
        self._server = await asyncio.start_server(self._on_connect, svc.host, svc.port)
        self._log.info(
            "listening",
            extra={"service": self.service_name, "listen": svc.listen,
                   "persona": svc.persona, "mode": self.config.mode,
                   "event": "listener_start"},
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # pragma: no cover
                pass
            self._server = None
        await self.drain()

    async def drain(self) -> None:
        if self._bg:
            await asyncio.gather(*list(self._bg), return_exceptions=True)

    def _schedule(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Track this connection task so drain()/stop() await in-flight handlers
        # (and their telemetry finalize) before the datastore is torn down.
        task = asyncio.current_task()
        if task is not None:
            self._bg.add(task)
            task.add_done_callback(self._bg.discard)
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        if self.kill_switch.is_engaged():
            self._log.warning("refusing connection: kill switch engaged",
                              extra={"src_ip": str(peer[0]), "event": "killswitch_refuse"})
            writer.close()
            return
        handle = await self.recorder.open_session(
            experiment_id=self.config.experiment_id,
            mode=self.config.mode,
            service=self.service_name,
            src_ip=str(peer[0]),
            src_port=int(peer[1]) if peer[1] else 0,
        )
        try:
            await self._handle(reader, writer, handle)
        except (ConnectionError, asyncio.IncompleteReadError, OSError, asyncio.TimeoutError):
            pass
        except Exception:  # never let a hostile client crash the loop
            self._log.exception("handler error", extra={"service": self.service_name})
        finally:
            await handle.close()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # pragma: no cover
                pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handle: SessionHandle,
    ) -> None:
        raise NotImplementedError
