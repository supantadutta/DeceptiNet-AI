#!/usr/bin/env python3
"""Emit per-session intelligence reports (Phase 4).

Usage:
    python scripts/analyze.py --all [--no-persist]
    python scripts/analyze.py --session <id>

Runs the classifier + IOC extractor + ATT&CK mapper over captured sessions and
prints JSON reports. With persistence (default), it also writes the
classification onto each session and the extracted IOCs/techniques to the
datastore. Reads only real captured data; fabricates nothing.
"""

from __future__ import annotations

import argparse
import json
import sys

sys.path.insert(0, ".")

from deceptinet.analysis.intel import analyze_all, analyze_session  # noqa: E402
from deceptinet.config.loader import load_config  # noqa: E402
from deceptinet.datastore.db import make_datastore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", help="datastore URL (default: from config.yaml)")
    ap.add_argument("--config", default=None)
    ap.add_argument("--session", help="analyze a single session id")
    ap.add_argument("--all", action="store_true", help="analyze all sessions")
    ap.add_argument("--no-persist", action="store_true", help="do not write results back")
    args = ap.parse_args()

    if not args.session and not args.all:
        ap.error("specify --session <id> or --all")

    url = args.db or load_config(args.config).datastore.url
    ds = make_datastore(url)
    ds.create_all()
    persist = not args.no_persist
    if args.session:
        reports = [analyze_session(ds, args.session, persist=persist)]
    else:
        reports = analyze_all(ds, persist=persist)
    ds.dispose()
    print(json.dumps(reports, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
