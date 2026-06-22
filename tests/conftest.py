"""Shared pytest fixtures."""

from __future__ import annotations

import socket

import pytest

from deceptinet.config.models import (
    AuthConfig,
    Config,
    HealthConfig,
    ServiceConfig,
    ServicesConfig,
)
from deceptinet.datastore.db import make_datastore


def free_port() -> int:
    """Pick an ephemeral free TCP port (config validation forbids literal 0)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def datastore():
    """A fresh on-disk SQLite datastore per test (temp file)."""
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    ds = make_datastore(f"sqlite:///{path}")
    ds.create_all()
    try:
        yield ds
    finally:
        ds.dispose()
        os.unlink(path)


def make_test_config(**overrides) -> Config:
    """Build a valid Phase-1 config for tests, overriding fields as needed."""
    services = ServicesConfig(
        ssh=ServiceConfig(enabled=True, listen=f"127.0.0.1:{free_port()}", persona="ubuntu-22.04-webserver"),
        http=ServiceConfig(enabled=True, listen=f"127.0.0.1:{free_port()}", persona="nginx-php-shop"),
        mysql=ServiceConfig(enabled=True, listen=f"127.0.0.1:{free_port()}", persona="mysql-8-prod"),
        pop3=ServiceConfig(enabled=True, listen=f"127.0.0.1:{free_port()}", persona="dovecot-mailhost"),
    )
    base = dict(
        mode="vanilla",
        experiment_id="test-exp",
        services=services,
        auth=AuthConfig(accept_after_attempts=2, accept_credentials=["root:root"]),
        health=HealthConfig(enabled=False, listen=f"127.0.0.1:{free_port()}"),
    )
    base.update(overrides)
    return Config(**base)


@pytest.fixture
def config() -> Config:
    return make_test_config()
