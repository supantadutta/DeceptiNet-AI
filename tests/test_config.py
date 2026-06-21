"""Config loading, validation, and env-override behaviour."""

from __future__ import annotations

import textwrap

import pytest
from pydantic import ValidationError

from deceptinet.config.loader import load_config

_VALID = """
deceptinet:
  mode: "vanilla"
  experiment_id: "exp-001"
  services:
    ssh:   { enabled: true,  listen: "0.0.0.0:2222", persona: "ubuntu-22.04-webserver" }
    http:  { enabled: false, listen: "0.0.0.0:8080", persona: "nginx-php-shop" }
    mysql: { enabled: false, listen: "0.0.0.0:3306", persona: "mysql-8-prod" }
    pop3:  { enabled: false, listen: "0.0.0.0:110",  persona: "dovecot-mailhost" }
  datastore:
    url: "sqlite:///data/deceptinet.sqlite3"
"""


def _write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(text))
    return p


def test_loads_valid_config(tmp_path):
    cfg = load_config(_write(tmp_path, _VALID))
    assert cfg.mode == "vanilla"
    assert cfg.services.ssh.enabled is True
    assert cfg.services.ssh.host == "0.0.0.0"
    assert cfg.services.ssh.port == 2222


def test_llm_mode_rejected_in_phase1(tmp_path):
    text = _VALID.replace('mode: "vanilla"', 'mode: "llm"')
    with pytest.raises(ValidationError, match="NOT IMPLEMENTED"):
        load_config(_write(tmp_path, text))


def test_egress_allow_is_forbidden(tmp_path):
    text = _VALID + "    containment:\n      egress: \"allow\"\n"
    # Indentation: append under deceptinet. Rebuild explicitly to be safe.
    text = """
deceptinet:
  mode: "vanilla"
  experiment_id: "exp-001"
  services:
    ssh:   { enabled: true,  listen: "0.0.0.0:2222", persona: "p" }
    http:  { enabled: false, listen: "0.0.0.0:8080", persona: "p" }
    mysql: { enabled: false, listen: "0.0.0.0:3306", persona: "p" }
    pop3:  { enabled: false, listen: "0.0.0.0:110",  persona: "p" }
  containment:
    egress: "allow"
"""
    with pytest.raises(ValidationError):
        load_config(_write(tmp_path, text))


def test_bad_listen_rejected(tmp_path):
    text = _VALID.replace('"0.0.0.0:2222"', '"not-a-listen"')
    with pytest.raises(ValidationError):
        load_config(_write(tmp_path, text))


def test_unknown_key_rejected(tmp_path):
    text = _VALID + "  bogus_key: true\n"
    with pytest.raises(ValidationError):
        load_config(_write(tmp_path, text))


def test_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("DECEPTINET_EXPERIMENT_ID", "exp-override")
    monkeypatch.setenv("DECEPTINET_SSH_LISTEN", "0.0.0.0:9999")
    cfg = load_config(_write(tmp_path, _VALID))
    assert cfg.experiment_id == "exp-override"
    assert cfg.services.ssh.port == 9999


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")
