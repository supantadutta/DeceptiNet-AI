"""SSH host-key management: load existing keys or generate + persist new ones.

A stable host key matters for the experiment: returning scanners key off the
host fingerprint, and a fingerprint that changes every restart is itself a
honeypot tell. Keys are written to a runtime data dir (gitignored) — they are
the honeypot's identity, not a secret to protect, but we still keep them out of
the repo.
"""

from __future__ import annotations

from pathlib import Path

import asyncssh

from deceptinet.logging_setup import get_logger

_log = get_logger("deceptinet.ssh.keys")

# (filename, asyncssh key algorithm) — both offered so the host looks like a
# stock OpenSSH server.
_KEY_SPECS = [
    ("ssh_host_ed25519_key", "ssh-ed25519"),
    ("ssh_host_rsa_key", "ssh-rsa"),
]


def load_or_generate_host_keys(directory: str | Path) -> list[asyncssh.SSHKey]:
    keydir = Path(directory)
    keydir.mkdir(parents=True, exist_ok=True)
    keys: list[asyncssh.SSHKey] = []
    for filename, algo in _KEY_SPECS:
        path = keydir / filename
        if path.exists():
            keys.append(asyncssh.read_private_key(str(path)))
            continue
        key = asyncssh.generate_private_key(algo)
        path.write_bytes(key.export_private_key())
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass
        keys.append(key)
        _log.info("generated SSH host key", extra={"algo": algo, "path": str(path)})
    return keys
