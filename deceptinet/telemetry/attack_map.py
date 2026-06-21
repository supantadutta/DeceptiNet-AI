"""MITRE ATT&CK technique mapper — NOT IMPLEMENTED (Phase 4).

Will map observed behaviours to ATT&CK techniques (e.g. T1110 brute force,
T1059 command execution, T1083 file/dir discovery) per spec §4. Deferred to
Phase 4; raw commands are captured now so mapping can run retrospectively over
stored data. See LIMITATIONS.md.
"""

from __future__ import annotations


def map_techniques(*args, **kwargs):  # pragma: no cover - intentional stub
    raise NotImplementedError(
        "ATT&CK mapper is NOT IMPLEMENTED yet (Phase 4). See LIMITATIONS.md."
    )
