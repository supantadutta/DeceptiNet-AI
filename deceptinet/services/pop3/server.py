"""POP3 honeypot (Phase 3).

Emulates USER/PASS/STAT/LIST/RETR/TOP/UIDL/DELE/NOOP/RSET/QUIT. Vanilla mode
serves a small canned mailbox; llm mode fabricates plausible message bodies for
RETR (falling back to canned on any failure). Every command is captured.

NOT IMPLEMENTED (see LIMITATIONS.md): APOP, STLS/TLS, real DELE persistence
across sessions, SASL.
"""

from __future__ import annotations

import asyncio
import datetime as _dt

from deceptinet.engine.prompts import pop3 as pop3_prompt
from deceptinet.services.base import TCPHoneypot
from deceptinet.telemetry.recorder import SessionHandle

# Canned mailbox (vanilla baseline). (subject, body)
_CANNED = [
    ("Welcome to the mail server",
     "From: admin@mailhost.local\r\nTo: user@mailhost.local\r\n"
     "Subject: Welcome to the mail server\r\n\r\n"
     "Your mailbox is ready. Contact IT with any issues.\r\n"),
    ("Invoice #4471",
     "From: billing@supplier.example\r\nTo: user@mailhost.local\r\n"
     "Subject: Invoice #4471\r\n\r\n"
     "Please find attached invoice #4471 for last month.\r\n"),
]


def _utcnow():
    return _dt.datetime.now(tz=_dt.timezone.utc)


class POP3Honeypot(TCPHoneypot):
    service_name = "pop3"

    async def _handle(self, reader, writer, handle: SessionHandle) -> None:
        user: str | None = None
        authed = False
        attempts = 0
        accept_after = self.config.auth.accept_after_attempts
        accept_creds = set(self.config.auth.accept_credentials)
        # Per-connection message bodies (canned; RETR may override via LLM).
        bodies = [b for _, b in _CANNED]

        writer.write(b"+OK DeceptiNet POP3 server ready\r\n")
        await writer.drain()

        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if not text:
                continue
            parts = text.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            ts = _utcnow()

            if cmd == "USER":
                user = arg
                resp = f"+OK {arg} is a valid mailbox\r\n"
            elif cmd == "PASS":
                attempts += 1
                cred = f"{user}:{arg}"
                accepted = cred in accept_creds or attempts >= accept_after
                await handle.record_credential(user or "", arg, "pop3", accepted, ts=ts)
                if accepted:
                    authed = True
                    resp = f"+OK mailbox ready, {len(bodies)} messages\r\n"
                else:
                    resp = "-ERR invalid password\r\n"
            elif not authed and cmd not in ("QUIT", "CAPA"):
                resp = "-ERR command not valid in this state\r\n"
            elif cmd == "STAT":
                total = sum(len(b) for b in bodies)
                resp = f"+OK {len(bodies)} {total}\r\n"
            elif cmd == "LIST":
                lines = [f"+OK {len(bodies)} messages:"]
                lines += [f"{i + 1} {len(b)}" for i, b in enumerate(bodies)]
                lines.append(".")
                resp = "\r\n".join(lines) + "\r\n"
            elif cmd == "UIDL":
                lines = [f"+OK {len(bodies)} messages:"]
                lines += [f"{i + 1} UID{i + 1:04d}" for i in range(len(bodies))]
                lines.append(".")
                resp = "\r\n".join(lines) + "\r\n"
            elif cmd in ("RETR", "TOP"):
                resp = await self._retr(arg, user or "user", bodies)
            elif cmd == "DELE":
                resp = "+OK message deleted\r\n"  # not persisted (see module docstring)
            elif cmd == "NOOP":
                resp = "+OK\r\n"
            elif cmd == "RSET":
                resp = "+OK\r\n"
            elif cmd == "CAPA":
                resp = "+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n"
            elif cmd == "QUIT":
                resp = "+OK DeceptiNet POP3 server signing off\r\n"
            else:
                resp = "-ERR unknown command\r\n"

            await handle.record_event(
                "command", command=text, response=resp[:2000],
                engine_mode=self.config.mode, ts=ts,
                meta={"authed": authed},
            )
            writer.write(resp.encode("utf-8", "replace"))
            await writer.drain()
            if cmd == "QUIT":
                break

    async def _retr(self, arg: str, user: str, bodies: list[str]) -> str:
        try:
            n = int(arg)
        except ValueError:
            return "-ERR no such message\r\n"
        if n < 1 or n > len(bodies):
            return "-ERR no such message\r\n"

        body = bodies[n - 1]
        if self.augmentor is not None:
            system, attacker_input, cache_key = pop3_prompt.build(self.persona, user, n)
            text, _meta = await self.augmentor.generate(
                service="pop3", persona=self.persona, cache_key=cache_key,
                system_prompt=system, session_summary="", attacker_input=attacker_input,
                max_tokens=self.config.llm.max_tokens, temperature=self.config.llm.temperature,
            )
            if text:
                body = text if text.endswith("\n") else text + "\r\n"
                bodies[n - 1] = body  # keep STAT/LIST roughly consistent thereafter
        # POP3 multiline: dot-stuff lines beginning with '.', terminate with CRLF.CRLF
        stuffed = "\r\n".join(
            ("." + ln if ln.startswith(".") else ln) for ln in body.replace("\r\n", "\n").split("\n")
        )
        return f"+OK message follows\r\n{stuffed}\r\n.\r\n"
