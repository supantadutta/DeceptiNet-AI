"""Structured JSON logging for DeceptiNet-AI.

All operational logs are emitted as one JSON object per line so they are
trivially queryable (jq, log shippers) and so the operational log stream is
clearly separable from the *captured attacker telemetry* (which lives in the
datastore, not here). We deliberately keep this dependency-free (stdlib only)
so it is easy to audit — a stated value of the project.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import sys
from typing import Any

# Standard LogRecord attributes we do NOT want to duplicate into the JSON body
# when callers pass `extra={...}`.
_RESERVED = set(
    logging.makeLogRecord({}).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Promote any caller-supplied `extra=` fields to top level.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _coerce(value)

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def _coerce(value: Any) -> Any:
    """Best-effort coercion of arbitrary extra values to JSON-serialisable."""
    if isinstance(value, (str, int, float, bool, type(None), list, dict)):
        return value
    return str(value)


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON formatter on the root logger (idempotent)."""
    root = logging.getLogger()
    root.setLevel(level.upper())

    # Replace existing handlers so re-invocation (tests, reload) stays clean.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
