"""Application runner: start listeners + health server, honour the kill switch.

This is the process entry point's workhorse. It is deliberately conservative:
only *implemented* services are started, enabled-but-unimplemented services emit
a loud NOT IMPLEMENTED warning rather than silently doing nothing, and the kill
switch is watched continuously so an operator can stop (and resume) all exposed
listeners at runtime.
"""

from __future__ import annotations

import asyncio
import os
import signal

import uvicorn

from deceptinet.config.models import Config
from deceptinet.containment.killswitch import KillSwitch
from deceptinet.dashboard.app import create_app
from deceptinet.datastore.db import Datastore, make_datastore
from deceptinet.engine.factory import get_engine
from deceptinet.logging_setup import get_logger
from deceptinet.services.ssh.server import SSHHoneypot
from deceptinet.telemetry.recorder import TelemetryRecorder

_log = get_logger("deceptinet.runner")

# Services that exist in config but are not implemented until Phase 3.
_PHASE3_SERVICES = ("http", "mysql", "pop3")


class _QuietUvicornServer(uvicorn.Server):
    """Uvicorn server that does NOT install its own signal handlers so the
    runner stays in control of shutdown."""

    def install_signal_handlers(self) -> None:  # noqa: D401
        return None


class Application:
    def __init__(self, config: Config, *, datastore: Datastore | None = None) -> None:
        self.config = config
        self.kill_switch = KillSwitch(config.containment.kill_switch_file)
        self.datastore = datastore or make_datastore(config.datastore.url)
        self.recorder = TelemetryRecorder(self.datastore)
        self.engine = get_engine(config)
        self.ssh: SSHHoneypot | None = None
        self._uvicorn: _QuietUvicornServer | None = None
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._host_key_dir = os.environ.get("DECEPTINET_HOSTKEY_DIR", "data/hostkeys")

    # ---- lifecycle ----------------------------------------------------
    async def start(self) -> None:
        self.datastore.create_all()
        self._warn_unimplemented_services()

        if self.config.services.ssh.enabled and not self.kill_switch.is_engaged():
            await self._start_ssh()
        elif self.kill_switch.is_engaged():
            _log.warning(
                "kill switch engaged at boot; listeners not started",
                extra={"event": "killswitch_boot"},
            )

        if self.config.health.enabled:
            await self._start_health()

        self._maybe_prewarm()
        self._tasks.append(asyncio.create_task(self._watch_kill_switch()))

    def _maybe_prewarm(self) -> None:
        """Pre-warm the LLM cache in the background (spec §2.2), if configured.

        Skipped for vanilla mode and the static provider. Makes real LLM calls,
        so it is gated behind cache.prewarm and logs a cost note.
        """
        if self.config.mode != "llm" or not self.config.cache.prewarm:
            return
        from deceptinet.engine.llm import DEFAULT_PREWARM_COMMANDS, LLMEngine

        if not isinstance(self.engine, LLMEngine) or self.engine.provider.name == "static":
            return

        async def _run() -> None:
            from deceptinet.session.state import build_session_state

            state = build_session_state(self.config.services.ssh.persona, "root")
            _log.warning(
                "pre-warming LLM cache (consumes tokens)",
                extra={"commands": len(DEFAULT_PREWARM_COMMANDS), "event": "prewarm_start"},
            )
            n = await self.engine.prewarm(DEFAULT_PREWARM_COMMANDS, state)
            _log.info("pre-warm complete", extra={"cached": n, "event": "prewarm_done"})

        self._tasks.append(asyncio.create_task(_run()))

    def _warn_unimplemented_services(self) -> None:
        for name in _PHASE3_SERVICES:
            svc = getattr(self.config.services, name)
            if svc.enabled:
                _log.warning(
                    "service enabled but NOT IMPLEMENTED (Phase 3); skipping",
                    extra={"service": name, "listen": svc.listen,
                           "event": "service_not_implemented"},
                )

    async def _start_ssh(self) -> None:
        self.ssh = SSHHoneypot(
            self.config,
            self.engine,
            self.recorder,
            self.kill_switch,
            host_key_dir=self._host_key_dir,
        )
        await self.ssh.start()

    async def _start_health(self) -> None:
        app = create_app(self.config, self.kill_switch, self.datastore)
        ucfg = uvicorn.Config(
            app,
            host=self.config.health.host,
            port=self.config.health.port,
            log_config=None,  # keep our JSON logging
            access_log=False,
        )
        self._uvicorn = _QuietUvicornServer(ucfg)
        self._tasks.append(asyncio.create_task(self._uvicorn.serve()))
        _log.info(
            "health endpoint listening",
            extra={"listen": self.config.health.listen, "event": "health_start"},
        )

    async def _watch_kill_switch(self) -> None:
        engaged_prev = self.kill_switch.is_engaged()
        while not self._stop.is_set():
            engaged = self.kill_switch.is_engaged()
            if engaged and not engaged_prev and self.ssh is not None:
                _log.warning("kill switch engaged: stopping listeners",
                             extra={"event": "killswitch_stop"})
                await self.ssh.stop()
                self.ssh = None
            elif (
                not engaged
                and engaged_prev
                and self.ssh is None
                and self.config.services.ssh.enabled
            ):
                _log.warning("kill switch released: resuming listeners",
                             extra={"event": "killswitch_resume"})
                await self._start_ssh()
            engaged_prev = engaged
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    async def serve_forever(self) -> None:
        await self.start()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass
        _log.info("deceptinet running; press Ctrl-C to stop",
                  extra={"event": "startup_complete"})
        await self._stop.wait()
        await self.shutdown()

    async def shutdown(self) -> None:
        _log.info("shutting down", extra={"event": "shutdown"})
        self._stop.set()
        if self.ssh is not None:
            await self.ssh.stop()
            self.ssh = None
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self.datastore.dispose()


async def run(config: Config) -> None:
    app = Application(config)
    await app.serve_forever()
