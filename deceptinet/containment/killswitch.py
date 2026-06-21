"""Kill switch (spec §2.3).

A single, file-based switch that, when engaged, causes the runner to stop all
exposed listeners and refuse new connections. File-based (rather than an API
call) on purpose: it works even if the process is wedged, can be triggered by
``make kill`` / ``touch``, and is trivial to reason about.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path


class KillSwitch:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def is_engaged(self) -> bool:
        return self._path.exists()

    def engage(self, reason: str = "manual") -> None:
        """Create the kill-switch file. Idempotent."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now(tz=_dt.timezone.utc).isoformat()
        self._path.write_text(
            f"DeceptiNet-AI kill switch engaged at {stamp}\nreason: {reason}\n",
            encoding="utf-8",
        )

    def disengage(self) -> None:
        """Remove the kill-switch file. Idempotent."""
        self._path.unlink(missing_ok=True)
