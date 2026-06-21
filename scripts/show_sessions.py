#!/usr/bin/env python3
"""Read-only datastore inspector: print captured sessions and their events.

Usage:
    python scripts/show_sessions.py [--db URL] [--limit N] [--events]

Defaults to the datastore URL in config.yaml. This is a developer/operator
convenience for inspecting captured telemetry; the Phase 6 dashboard will
provide a richer, web-based replacement. It NEVER modifies data.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

# Allow running directly from the repo root (python scripts/show_sessions.py).
sys.path.insert(0, ".")

from deceptinet.config.loader import load_config  # noqa: E402
from deceptinet.datastore.db import make_datastore  # noqa: E402
from deceptinet.datastore.models import Credential, Event, Session  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", help="datastore URL (default: from config.yaml)")
    ap.add_argument("--config", default=None, help="path to config.yaml")
    ap.add_argument("--limit", type=int, default=20, help="max sessions to show")
    ap.add_argument("--events", action="store_true", help="also print every event")
    args = ap.parse_args()

    url = args.db
    if url is None:
        url = load_config(args.config).datastore.url

    ds = make_datastore(url)
    ds.create_all()  # safe no-op if tables exist
    with ds.session() as s:
        sessions = s.scalars(
            select(Session).order_by(Session.started_at.desc()).limit(args.limit)
        ).all()
        if not sessions:
            print(f"(no sessions in {url})")
            return 0
        print(f"=== {len(sessions)} most-recent session(s) in {url} ===\n")
        for sess in sessions:
            dur = f"{sess.duration_s:.2f}s" if sess.duration_s is not None else "open"
            print(
                f"[{sess.service}/{sess.mode}] {sess.src_ip}:{sess.src_port}  "
                f"id={sess.id[:12]}  class={sess.session_classification}  "
                f"events={sess.event_count}  dur={dur}"
            )
            print(f"    client : {sess.client_version}  term={sess.term_type}")
            creds = s.scalars(
                select(Credential).where(Credential.session_id == sess.id).order_by(Credential.ts)
            ).all()
            for c in creds:
                mark = "ACCEPTED" if c.accepted else "rejected"
                print(f"    cred   : {c.username}:{c.password}  [{mark}]")
            if args.events:
                events = s.scalars(
                    select(Event).where(Event.session_id == sess.id).order_by(Event.seq)
                ).all()
                for e in events:
                    label = e.command if e.command else e.event_type
                    lat = f" {e.latency_ms:.1f}ms" if e.latency_ms is not None else ""
                    print(f"      #{e.seq:<3} {e.event_type:<14} {label!r}{lat}")
            print()
    ds.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
