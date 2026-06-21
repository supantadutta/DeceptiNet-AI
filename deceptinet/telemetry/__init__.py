"""Telemetry & capture layer (spec §3).

Phase 1: capture every interaction as a structured, queryable row
(:class:`TelemetryRecorder`). Phase 4 adds the session classifier, IOC
extractor, and MITRE ATT&CK mapper — those are present here only as honest
stubs that return "unknown"/empty rather than guessing.
"""

from deceptinet.telemetry.recorder import SessionHandle, TelemetryRecorder

__all__ = ["TelemetryRecorder", "SessionHandle"]
