"""SSH honeypot listener (Phase 1).

Accepts connections, presents a realistic OpenSSH banner, captures every
credential attempt, lets the attacker "in" after N attempts, allocates a PTY,
and runs an interactive shell loop whose responses come from the configured
response engine (vanilla in Phase 1). Every interaction is recorded as
structured telemetry.

Containment invariants (spec §2.3):
  * No real command execution — the engine only ever reads/writes the in-memory
    virtual filesystem.
  * Honours the kill switch: new connections are refused while it is engaged.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
from dataclasses import dataclass, field

import asyncssh

from deceptinet.config.models import Config
from deceptinet.containment.killswitch import KillSwitch
from deceptinet.engine.base import ResponseEngine
from deceptinet.logging_setup import get_logger
from deceptinet.services.ssh.keys import load_or_generate_host_keys
from deceptinet.session.state import SessionState, build_session_state
from deceptinet.telemetry.recorder import SessionHandle, TelemetryRecorder

_log = get_logger("deceptinet.ssh")


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


@dataclass
class _ConnCtx:
    """Per-connection state shared between the SSHServer callbacks and the
    process handler."""

    peer_ip: str
    peer_port: int
    client_version: str | None = None
    term_type: str | None = None
    accepted_username: str | None = None
    # (username, password, method, accepted, ts)
    pending_credentials: list[tuple] = field(default_factory=list)
    attempts: int = 0
    handle: SessionHandle | None = None
    state: SessionState | None = None
    session_opening: bool = False
    finalized: bool = False


class SSHHoneypot:
    def __init__(
        self,
        config: Config,
        engine: ResponseEngine,
        recorder: TelemetryRecorder,
        kill_switch: KillSwitch,
        *,
        host_key_dir: str = "data/hostkeys",
    ) -> None:
        self.config = config
        self.engine = engine
        self.recorder = recorder
        self.kill_switch = kill_switch
        self._host_key_dir = host_key_dir
        self._server: asyncssh.SSHAcceptor | None = None
        self._bg_tasks: set[asyncio.Task] = set()
        self._server_version = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"

    @property
    def bound_port(self) -> int | None:
        if self._server is None:
            return None
        return self._server.get_port()

    async def start(self) -> None:
        svc = self.config.services.ssh
        host_keys = load_or_generate_host_keys(self._host_key_dir)
        self._server = await asyncssh.listen(
            host=svc.host,
            port=svc.port,
            server_factory=self._make_server,
            process_factory=self._handle_process,
            server_host_keys=host_keys,
            server_version=self._server_version,
            # Built-in line editor handles echo/backspace/history for the PTY.
            line_editor=True,
            encoding="utf-8",
            # We accept attacker input as untrusted data; keep limits sane.
            login_timeout=120,
            keepalive_interval=0,
        )
        _log.info(
            "ssh honeypot listening",
            extra={"listen": svc.listen, "persona": svc.persona,
                   "mode": self.config.mode, "event": "listener_start"},
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # pragma: no cover - best-effort shutdown
                pass
            self._server = None
        await self.drain()

    async def drain(self) -> None:
        """Await any outstanding background finalization tasks (used by tests
        and graceful shutdown)."""
        if self._bg_tasks:
            await asyncio.gather(*list(self._bg_tasks), return_exceptions=True)

    # ---- asyncssh factories/callbacks --------------------------------
    def _make_server(self) -> "_HoneypotSSHServer":
        return _HoneypotSSHServer(self)

    def _schedule(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _open_session(self, ctx: _ConnCtx, *, term_type: str | None) -> SessionHandle:
        handle = await self.recorder.open_session(
            experiment_id=self.config.experiment_id,
            mode=self.config.mode,
            service="ssh",
            src_ip=ctx.peer_ip,
            src_port=ctx.peer_port,
            client_version=ctx.client_version,
            term_type=term_type,
        )
        # Flush every credential attempt captured before the shell opened.
        for username, password, method, accepted, ts in ctx.pending_credentials:
            await handle.record_credential(username, password, method, accepted, ts=ts)
        return handle

    async def _finalize_ctx(self, ctx: _ConnCtx) -> None:
        if ctx.finalized:
            return
        ctx.finalized = True
        try:
            if ctx.handle is None:
                # Probe-only connection (auth attempts and/or a connect with no
                # shell). Still worth recording — it's real reconnaissance data.
                handle = await self._open_session(ctx, term_type=None)
                await handle.close(meta={"probe_only": True})
            else:
                await ctx.handle.close()
        except Exception:  # pragma: no cover - never let telemetry crash the loop
            _log.exception("error finalizing session", extra={"src_ip": ctx.peer_ip})

    # ---- process handling (interactive shell / exec) -----------------
    async def _handle_process(self, process: asyncssh.SSHServerProcess) -> None:
        ctx: _ConnCtx | None = process.get_extra_info("honeypot_ctx")
        if ctx is None:  # pragma: no cover - should never happen
            _log.error("no honeypot_ctx on process; closing")
            process.exit(1)
            return

        term_type = process.get_terminal_type()
        ctx.term_type = term_type
        # client_version is known post version-exchange; capture before we write
        # the session row so it is persisted from the start.
        ctx.client_version = process.get_extra_info("client_version") or ctx.client_version
        username = ctx.accepted_username or "root"
        ctx.state = build_session_state(self.config.services.ssh.persona, username)

        ctx.session_opening = True
        ctx.handle = await self._open_session(ctx, term_type=term_type)
        await ctx.handle.record_event(
            "login_success",
            command=None,
            engine_mode=self.engine.mode,
            meta={"username": username, "attempts": ctx.attempts},
        )

        try:
            if process.command is not None:
                await self._run_exec(process, ctx)
            elif process.subsystem:
                # e.g. sftp — not emulated in Phase 1; record and refuse.
                await ctx.handle.record_event(
                    "subsystem_request", command=process.subsystem,
                    meta={"not_implemented": True},
                )
                process.stderr.write("This service allows shell access only.\n")
                process.exit(1)
            else:
                await self._run_shell(process, ctx)
        except (asyncssh.Error, OSError, ConnectionError):
            # Client vanished / transport error — expected with hostile clients.
            pass
        finally:
            await self._finalize_ctx(ctx)
            if not process.is_closing():
                try:
                    process.exit(0)
                except Exception:  # pragma: no cover
                    pass

    async def _run_exec(self, process: asyncssh.SSHServerProcess, ctx: _ConnCtx) -> None:
        """Non-interactive ``ssh host 'cmd'`` — very common for automated tools."""
        raw = process.command or ""
        last_status = 0
        # Bots frequently chain commands across newlines in a single exec.
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            ts = _utcnow()
            result = await self.engine.respond(line, ctx.state)
            await ctx.handle.record_event(
                "exec_command",
                command=line,
                response=result.output,
                exit_status=result.exit_status,
                latency_ms=result.latency_ms,
                cache_hit=result.cache_hit,
                engine_mode=result.engine_mode,
                meta=result.meta or None,
                ts=ts,
            )
            if result.output:
                process.stdout.write(result.output)
            last_status = result.exit_status
            if result.close_session:
                break
        process.exit(last_status)

    async def _run_shell(self, process: asyncssh.SSHServerProcess, ctx: _ConnCtx) -> None:
        state = ctx.state
        handle = ctx.handle
        process.stdout.write(_motd(state))
        while True:
            process.stdout.write(state.prompt())
            try:
                line = await process.stdin.readline()
            except asyncssh.BreakReceived:
                process.stdout.write("\n")
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            except (asyncssh.Error, OSError):
                break
            if not line:  # EOF (Ctrl-D / disconnect)
                process.stdout.write("logout\n")
                break
            ts = _utcnow()
            cmd = line.rstrip("\r\n")
            if not cmd.strip():
                continue
            result = await self.engine.respond(cmd, state)
            await handle.record_event(
                "command",
                command=cmd,
                response=result.output,
                exit_status=result.exit_status,
                latency_ms=result.latency_ms,
                cache_hit=result.cache_hit,
                engine_mode=result.engine_mode,
                meta=result.meta or None,
                ts=ts,
            )
            if result.output:
                process.stdout.write(result.output)
            if result.close_session:
                break


class _HoneypotSSHServer(asyncssh.SSHServer):
    """One instance per connection. Captures peer + credentials, then hands off
    to the process handler via shared :class:`_ConnCtx`."""

    def __init__(self, hp: SSHHoneypot) -> None:
        self._hp = hp
        self._ctx: _ConnCtx | None = None
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        ctx = _ConnCtx(peer_ip=str(peer[0]), peer_port=int(peer[1]) if peer[1] else 0)
        self._ctx = ctx
        # Make the ctx retrievable from the process handler.
        conn.set_extra_info(honeypot_ctx=ctx)

        # Refuse service while the kill switch is engaged (spec §2.3).
        if self._hp.kill_switch.is_engaged():
            _log.warning(
                "refusing connection: kill switch engaged",
                extra={"src_ip": ctx.peer_ip, "event": "killswitch_refuse"},
            )
            conn.close()

    def connection_lost(self, exc: Exception | None) -> None:
        ctx = self._ctx
        if ctx is None:
            return
        # client_version is known after version exchange.
        if self._conn is not None:
            ctx.client_version = self._conn.get_extra_info("client_version")
        if not ctx.finalized:
            self._hp._schedule(self._hp._finalize_ctx(ctx))

    def begin_auth(self, username: str) -> bool:
        # Require auth so we always capture at least one credential attempt.
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        # Force password auth to maximise credential capture.
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        ctx = self._ctx
        assert ctx is not None
        if self._conn is not None and ctx.client_version is None:
            ctx.client_version = self._conn.get_extra_info("client_version")
        ctx.attempts += 1
        cred = f"{username}:{password}"
        accept = (
            cred in self._hp.config.auth.accept_credentials
            or ctx.attempts >= self._hp.config.auth.accept_after_attempts
        )
        ctx.pending_credentials.append(
            (username, password, "password", accept, _utcnow())
        )
        _log.info(
            "auth attempt",
            extra={"src_ip": ctx.peer_ip, "username": username,
                   "accepted": accept, "attempt": ctx.attempts,
                   "event": "auth_attempt"},
        )
        if accept:
            ctx.accepted_username = username
        return accept


def _motd(state: SessionState) -> str:
    p = state.persona
    return (
        f"Welcome to {p.pretty_name} (GNU/Linux {p.kernel} {p.arch})\n"
        "\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/advantage\n"
        "\n"
        "Last login: Mon Oct 30 11:59:01 2023 from 10.0.0.5\n"
    )
