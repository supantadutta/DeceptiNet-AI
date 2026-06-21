"""Containment proof: the honeypot never executes real commands (spec §2.3, AC#3).

Two complementary checks:
  1. Behavioural — honeypot `rm`/`cat` against a REAL host path must not touch
     the host or leak real file contents (it operates only on the in-memory VFS).
  2. Static — no module in the package imports/uses a real-execution primitive
     (subprocess, os.system/popen, pty.spawn, ...).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import deceptinet
from deceptinet.engine.vanilla import VanillaEngine
from deceptinet.session.state import build_session_state

_FORBIDDEN = [
    r"\bimport\s+subprocess\b",
    r"\bsubprocess\.",
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\bos\.exec[lv]",
    r"\bpty\.spawn\b",
    r"\bcommands\.getoutput\b",
    r"\bpopen2\b",
]


async def test_rm_does_not_touch_real_host(tmp_path):
    real_file = tmp_path / "real_secret.txt"
    real_file.write_text("REAL-HOST-SECRET")

    engine = VanillaEngine()
    state = build_session_state("ubuntu-22.04-webserver", "root")

    # Attempt to remove the real path through the honeypot.
    await engine.respond(f"rm -f {real_file}", state)
    assert real_file.exists(), "honeypot rm must not delete real host files"

    # Attempt to read it: the honeypot must NOT return real contents.
    result = await engine.respond(f"cat {real_file}", state)
    assert "REAL-HOST-SECRET" not in result.output
    assert "No such file or directory" in result.output


def test_no_real_execution_primitives_in_source():
    pkg_root = Path(deceptinet.__file__).parent
    offenders: list[str] = []
    for py in pkg_root.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN:
            if re.search(pattern, text):
                offenders.append(f"{py.relative_to(pkg_root)}: matched /{pattern}/")
    assert not offenders, "real-execution primitive found in source:\n" + "\n".join(offenders)
