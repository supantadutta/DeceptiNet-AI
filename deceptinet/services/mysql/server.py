"""MySQL honeypot (Phase 3).

Sends a believable handshake, captures the login username, accepts auth, and
answers COM_QUERY with a common-query subset (vanilla canned tables; llm
fabricates result sets for novel SELECT/SHOW). Other commands get a lenient OK
and are tagged. See protocol.py for the explicit NOT IMPLEMENTED list.
"""

from __future__ import annotations

import datetime as _dt
import os

from deceptinet.engine.prompts import mysql as mysql_prompt
from deceptinet.services.base import TCPHoneypot
from deceptinet.services.mysql import protocol as proto
from deceptinet.telemetry.recorder import SessionHandle

_SERVER_VERSION = "8.0.35-0ubuntu0.22.04.1"

# COM_* command bytes
_COM_QUIT = 0x01
_COM_INIT_DB = 0x02
_COM_QUERY = 0x03
_COM_FIELD_LIST = 0x04
_COM_PING = 0x0E


def _utcnow():
    return _dt.datetime.now(tz=_dt.timezone.utc)


class MySQLHoneypot(TCPHoneypot):
    service_name = "mysql"

    async def _handle(self, reader, writer, handle: SessionHandle) -> None:
        conn_id = int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF
        writer.write(proto.frame(proto.build_handshake(conn_id, _SERVER_VERSION), 0))
        await writer.drain()

        # Handshake response (auth). We accept any credentials.
        try:
            _seq, payload = await proto.read_packet(reader)
        except Exception:
            return
        username = proto.parse_handshake_response(payload)
        await handle.record_credential(username, None, "mysql", accepted=True, ts=_utcnow())
        writer.write(proto.frame(proto.ok_packet(), 2))  # auth OK
        await writer.drain()

        # Command phase.
        while True:
            try:
                _seq, payload = await proto.read_packet(reader)
            except Exception:
                break
            if not payload:
                break
            cmd = payload[0]
            ts = _utcnow()

            if cmd == _COM_QUIT:
                break
            if cmd == _COM_PING:
                writer.write(proto.frame(proto.ok_packet(), 1))
                await writer.drain()
                await handle.record_event("mysql_command", command="PING",
                                          engine_mode=self.config.mode, ts=ts)
                continue
            if cmd == _COM_INIT_DB:
                db = payload[1:].decode("utf-8", "replace")
                writer.write(proto.frame(proto.ok_packet(), 1))
                await writer.drain()
                await handle.record_event("mysql_command", command=f"USE {db}",
                                          engine_mode=self.config.mode, ts=ts)
                continue
            if cmd == _COM_FIELD_LIST:
                writer.write(proto.frame(proto.eof_packet(), 1))
                await writer.drain()
                continue
            if cmd == _COM_QUERY:
                query = payload[1:].decode("utf-8", "replace")
                packets, responder, meta = await self._answer(query)
                seq = 1
                for p in packets:
                    writer.write(proto.frame(p, seq))
                    seq += 1
                await writer.drain()
                await handle.record_event(
                    "mysql_query", command=query,
                    response=f"{responder}: {len(packets)} packets"[:2000],
                    engine_mode=self.config.mode, ts=ts,
                    meta={"responder": responder, **meta},
                )
                continue

            # Unsupported command: lenient OK, recorded honestly.
            writer.write(proto.frame(proto.ok_packet(), 1))
            await writer.drain()
            await handle.record_event(
                "mysql_command", command=f"COM_{cmd:#04x}",
                engine_mode=self.config.mode, ts=ts,
                meta={"not_implemented": True},
            )

    async def _answer(self, query: str):
        q = query.strip().rstrip(";").strip()
        low = " ".join(q.split()).lower()

        if low in ("select version()", "select @@version", "select @@version_comment"):
            col = q.split()[-1] if q.split() else "version()"
            return proto.build_result_set([col], [[_SERVER_VERSION]]), "template", {}
        if low == "show databases":
            return proto.build_result_set(
                ["Database"],
                [["information_schema"], ["mysql"], ["performance_schema"], ["shopdb"]],
            ), "template", {}
        if low == "show tables":
            return proto.build_result_set(
                ["Tables_in_shopdb"], [["users"], ["orders"], ["products"], ["sessions"]]
            ), "template", {}
        if low in ("select database()", "select schema()"):
            return proto.build_result_set(["database()"], [["shopdb"]]), "template", {}
        if low in ("select user()", "select current_user()", "select current_user"):
            return proto.build_result_set(["user()"], [["root@localhost"]]), "template", {}

        if low.startswith(("select", "show", "describe", "desc ")):
            if self.augmentor is not None:
                system, qin, key = mysql_prompt.build(self.persona, q)
                text, meta = await self.augmentor.generate(
                    service="mysql", persona=self.persona, cache_key=key,
                    system_prompt=system, session_summary="", attacker_input=qin,
                    max_tokens=self.config.llm.max_tokens,
                    temperature=self.config.llm.temperature,
                )
                if text:
                    parsed = mysql_prompt.parse_tsv(text)
                    if parsed:
                        cols, rows = parsed
                        return proto.build_result_set(cols, rows), "llm", meta
                    return [proto.ok_packet()], "llm", meta
            # No LLM / fallback: an empty, well-formed result set.
            return proto.build_result_set(["result"], []), "template_fallback", {}

        # DML/DDL/SET/USE etc. -> OK.
        return [proto.ok_packet()], "template", {}
