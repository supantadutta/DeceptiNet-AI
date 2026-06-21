"""IOC extractor — NOT IMPLEMENTED (Phase 4).

Will extract IPs, domains, URLs, hashes, downloaded-payload references,
credentials tried, and wallet addresses from captured sessions (spec §4). Raw
material is already captured verbatim in the datastore (commands, credentials),
so no intelligence is lost by deferring extraction. See LIMITATIONS.md.
"""

from __future__ import annotations


def extract_iocs(*args, **kwargs):  # pragma: no cover - intentional stub
    raise NotImplementedError(
        "IOC extractor is NOT IMPLEMENTED yet (Phase 4). See LIMITATIONS.md."
    )
