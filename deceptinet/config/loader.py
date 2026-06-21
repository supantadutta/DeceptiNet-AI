"""Load + validate configuration from YAML with environment overrides.

Precedence (lowest to highest):
  1. Defaults baked into the pydantic models.
  2. Values in the YAML file (``config.yaml`` by default).
  3. A curated set of ``DECEPTINET_*`` environment variables (documented in
     ``.env.example``) — these exist so Docker/experiment runs can flip the
     experimental switches without editing files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from deceptinet.config.models import Config

DEFAULT_CONFIG_PATH = "config.yaml"

# Map of ENV VAR -> dotted path inside the config tree.
_ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "DECEPTINET_MODE": ("mode",),
    "DECEPTINET_EXPERIMENT_ID": ("experiment_id",),
    "DECEPTINET_DATASTORE_URL": ("datastore", "url"),
    "DECEPTINET_LLM_PROVIDER": ("llm", "provider"),
    "DECEPTINET_SSH_LISTEN": ("services", "ssh", "listen"),
    "DECEPTINET_SSH_ENABLED": ("services", "ssh", "enabled"),
    "DECEPTINET_HEALTH_LISTEN": ("health", "listen"),
    "DECEPTINET_KILL_SWITCH_FILE": ("containment", "kill_switch_file"),
    "DECEPTINET_EGRESS": ("containment", "egress"),
    "DECEPTINET_LOG_LEVEL": ("logging", "level"),
}

_BOOL_PATHS = {("services", "ssh", "enabled")}


def _coerce_env_value(path: tuple[str, ...], raw: str) -> Any:
    if path in _BOOL_PATHS:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return raw


def _set_in(tree: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = tree
    for key in path[:-1]:
        node = node.setdefault(key, {})
        if not isinstance(node, dict):
            raise ValueError(
                f"env override path {'.'.join(path)} collides with a non-mapping value"
            )
    node[path[-1]] = value


def _apply_env_overrides(tree: dict[str, Any]) -> list[str]:
    applied: list[str] = []
    for env_var, path in _ENV_OVERRIDES.items():
        if env_var in os.environ:
            _set_in(tree, path, _coerce_env_value(path, os.environ[env_var]))
            applied.append(env_var)
    return applied


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load, env-override, and validate the configuration.

    The config file location resolves from (in order): the ``path`` argument,
    the ``DECEPTINET_CONFIG`` env var, then ``./config.yaml``.
    """
    resolved = (
        Path(path)
        if path is not None
        else Path(os.environ.get("DECEPTINET_CONFIG", DEFAULT_CONFIG_PATH))
    )
    if not resolved.is_file():
        raise FileNotFoundError(
            f"config file not found: {resolved} "
            "(set DECEPTINET_CONFIG or pass a path; copy config.yaml from the repo root)"
        )

    with resolved.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    if "deceptinet" not in raw:
        raise ValueError(
            f"{resolved}: expected a top-level 'deceptinet:' key (see config.yaml in the repo)"
        )

    tree = raw["deceptinet"]
    if not isinstance(tree, dict):
        raise ValueError(f"{resolved}: 'deceptinet' must be a mapping")

    _apply_env_overrides(tree)

    # pydantic raises a precise, aggregated ValidationError on bad input.
    return Config.model_validate(tree)
