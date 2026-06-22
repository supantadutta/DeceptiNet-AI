"""HTTP honeypot (Phase 3).

A minimal HTTP/1.1 listener that captures full requests (method, path, headers,
user-agent, body/payloads). Vanilla mode serves a few templated pages and 404s
unknown paths; llm mode generates plausible bodies for novel paths. Common
attack probes (SQLi/LFI/traversal/webshell) are tagged in event meta as a cheap
signal (full MITRE ATT&CK mapping is Phase 4).

One request per connection (Connection: close) — robust against the
pipelining/keep-alive long tail. NEVER serves real files or executes anything.
"""

from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import unquote_plus

from deceptinet.engine.prompts import http as http_prompt
from deceptinet.services.base import TCPHoneypot
from deceptinet.telemetry.recorder import SessionHandle

_MAX_BODY = 65536

_STATUS_TEXT = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found"}

_INDEX = (
    "<!DOCTYPE html><html><head><title>ShopFast</title></head>"
    "<body><h1>ShopFast</h1><p>Welcome. <a href=\"/login\">Sign in</a></p></body></html>\n"
)
_LOGIN = (
    "<!DOCTYPE html><html><head><title>Sign in</title></head><body>"
    "<h1>Sign in</h1><form method=\"post\" action=\"/login\">"
    "<input name=\"username\"><input name=\"password\" type=\"password\">"
    "<button>Login</button></form></body></html>\n"
)
_ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
_404 = (
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
    "<body><h1>404 Not Found</h1></body></html>\n"
)

# path (without query) -> (status, body)
_TEMPLATES = {
    "/": (200, _INDEX),
    "/index.html": (200, _INDEX),
    "/login": (200, _LOGIN),
    "/admin": (200, _LOGIN),
    "/admin/": (200, _LOGIN),
    "/wp-login.php": (200, _LOGIN),
    "/administrator": (200, _LOGIN),
    "/robots.txt": (200, _ROBOTS),
}

_ATTACK_PATTERNS = [
    ("sqli", re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bsleep\(|information_schema)", re.I)),
    ("traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.I)),
    ("lfi", re.compile(r"(/etc/passwd|php://|data://|file://)", re.I)),
    ("webshell", re.compile(r"(c99|r57|eval\(|base64_decode\(|system\(|passthru\()", re.I)),
    ("xss", re.compile(r"(<script>|onerror=|javascript:)", re.I)),
]


def _utcnow():
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _detect_attacks(path: str, body: str) -> list[str]:
    raw = f"{path}\n{body}"
    # Match against both raw and URL-decoded forms (form encoding uses '+'/%xx).
    hay = raw + "\n" + unquote_plus(raw)
    return [name for name, pat in _ATTACK_PATTERNS if pat.search(hay)]


class HTTPHoneypot(TCPHoneypot):
    service_name = "http"

    async def _handle(self, reader, writer, handle: SessionHandle) -> None:
        request_line = await reader.readline()
        if not request_line:
            return
        ts = _utcnow()
        try:
            method, raw_path, _ = request_line.decode("utf-8", "replace").split()
        except ValueError:
            self._write(writer, 400, "Bad Request\n")
            await writer.drain()
            return

        headers: dict[str, str] = {}
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            k, _, v = h.decode("utf-8", "replace").partition(":")
            if k:
                headers[k.strip().lower()] = v.strip()

        body = ""
        try:
            clen = min(int(headers.get("content-length", "0") or 0), _MAX_BODY)
        except ValueError:
            clen = 0
        if clen:
            raw = await reader.read(clen)
            body = raw.decode("utf-8", "replace")

        path = raw_path.split("?", 1)[0]
        status, resp_body, responder = await self._respond(method, raw_path, path, headers, body)
        attacks = _detect_attacks(raw_path, body)

        await handle.record_event(
            "http_request",
            command=f"{method} {raw_path}",
            response=resp_body[:2000],
            exit_status=status,
            engine_mode=self.config.mode,
            ts=ts,
            meta={
                "user_agent": headers.get("user-agent"),
                "responder": responder,
                "attack_hints": attacks or None,
                "has_body": bool(body),
            },
        )
        self._write(writer, status, resp_body)
        await writer.drain()

    async def _respond(self, method, raw_path, path, headers, body):
        if path in _TEMPLATES:
            status, tmpl = _TEMPLATES[path]
            return status, tmpl, "template"

        # Novel path: try the LLM (llm mode), else 404.
        if self.augmentor is not None:
            system, attacker_input, cache_key = http_prompt.build(
                self.persona, method, raw_path, headers, body
            )
            text, _meta = await self.augmentor.generate(
                service="http", persona=self.persona, cache_key=cache_key,
                system_prompt=system, session_summary="", attacker_input=attacker_input,
                max_tokens=self.config.llm.max_tokens, temperature=self.config.llm.temperature,
            )
            if text:
                return 200, text if text.endswith("\n") else text + "\n", "llm"
        return 404, _404, "template"

    def _write(self, writer, status: int, body: str) -> None:
        data = body.encode("utf-8", "replace")
        reason = _STATUS_TEXT.get(status, "OK")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Server: nginx/1.18.0 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(data)}\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(head.encode("ascii", "replace") + data)
