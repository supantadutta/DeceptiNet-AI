"""Protocol emulation layer: one adapter per emulated service (spec §3).

Phase 1 implements SSH. HTTP / MySQL / POP3 arrive in Phase 3 (see
LIMITATIONS.md). Adapters parse real protocol framing, extract attacker input as
structured interaction events, and NEVER execute anything.
"""
