"""Validated configuration models (pydantic v2).

These mirror ``config.yaml`` (spec §4). The two switches that drive the whole
A/B thesis experiment are :attr:`Config.mode` (``llm`` | ``vanilla``) and
:attr:`LLMConfig.provider`. Validation here is intentionally strict: a
misconfigured honeypot is a safety problem, not just a bug.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

Mode = Literal["llm", "vanilla"]
Provider = Literal["claude", "ollama", "openai_compat", "static"]
# NOTE: "allow" is deliberately NOT a permitted egress value (spec §2.3).
EgressPolicy = Literal["deny", "allow_llm_only"]


def _validate_listen(value: str) -> str:
    """Validate a ``host:port`` listen string."""
    if value.count(":") < 1:
        raise ValueError(f"listen must be 'host:port', got {value!r}")
    host, _, port = value.rpartition(":")
    if not host:
        raise ValueError(f"listen is missing a host: {value!r}")
    try:
        port_i = int(port)
    except ValueError as exc:
        raise ValueError(f"listen port is not an integer: {value!r}") from exc
    if not (0 < port_i < 65536):
        raise ValueError(f"listen port out of range: {value!r}")
    return value


class ServiceConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    listen: str
    persona: str

    @field_validator("listen")
    @classmethod
    def _check_listen(cls, v: str) -> str:
        return _validate_listen(v)

    @property
    def host(self) -> str:
        return self.listen.rpartition(":")[0]

    @property
    def port(self) -> int:
        return int(self.listen.rpartition(":")[2])


class ServicesConfig(BaseModel):
    model_config = {"extra": "forbid"}

    ssh: ServiceConfig
    http: ServiceConfig
    mysql: ServiceConfig
    pop3: ServiceConfig


class LLMConfig(BaseModel):
    model_config = {"extra": "forbid"}

    provider: Provider = "static"
    model: str = "claude-sonnet-4-6"
    max_tokens: int = Field(default=600, gt=0)
    temperature: float = Field(default=0.4, ge=0.0, le=2.0)
    timeout_s: float = Field(default=8.0, gt=0)
    fallback_provider: Provider = "static"
    # Connection settings for non-Claude / self-hosted providers.
    #   ollama        -> base_url like "http://ollama:11434"
    #   openai_compat -> base_url like "http://vllm:8000/v1"
    # api_key is optional; prefer an environment variable (api_key_env) so secrets
    # stay out of config files. For Claude the SDK reads ANTHROPIC_API_KEY by default.
    base_url: str | None = None
    api_key: str | None = None
    api_key_env: str | None = None
    # Hybrid behaviour: when true, the LLM only handles commands the vanilla
    # engine cannot (the "long tail"); known commands stay deterministic so
    # session state remains consistent. See METHODOLOGY.md / DECISIONS.md.
    augment_only: bool = True


class CacheConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = True
    semantic: bool = True
    prewarm: bool = True


class LatencyConfig(BaseModel):
    model_config = {"extra": "forbid"}

    inject_jitter_on_cache: bool = False
    target_profile: str = "realistic"


class ContainmentConfig(BaseModel):
    model_config = {"extra": "forbid"}

    egress: EgressPolicy = "deny"
    kill_switch_file: str = "/run/deceptinet.stop"


class TelemetryConfig(BaseModel):
    model_config = {"extra": "forbid"}

    classify_sessions: bool = True
    extract_iocs: bool = True
    attack_mapping: str = "mitre"


class DatastoreConfig(BaseModel):
    model_config = {"extra": "forbid"}

    # Default to a local SQLite file so the system is runnable on a laptop with
    # zero external services (spec §3: "sqlite fallback for laptop testing").
    url: str = "sqlite:///data/deceptinet.sqlite3"


class AuthConfig(BaseModel):
    """SSH/login auth behaviour for the honeypot front door.

    The honeypot logs every credential attempt and then *lets the attacker in*
    so we can observe post-auth behaviour. ``accept_after_attempts`` controls
    how many attempts occur before access is granted (Cowrie-style).
    """

    model_config = {"extra": "forbid"}

    accept_after_attempts: int = Field(default=2, ge=1)
    # Credentials that are accepted immediately on the first try (weak creds an
    # attacker "guessed"). Empty list => only the attempt-count rule applies.
    accept_credentials: list[str] = Field(
        default_factory=lambda: ["root:root", "root:123456", "admin:admin"]
    )


class HealthConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = True
    listen: str = "0.0.0.0:8000"

    @field_validator("listen")
    @classmethod
    def _check_listen(cls, v: str) -> str:
        return _validate_listen(v)

    @property
    def host(self) -> str:
        return self.listen.rpartition(":")[0]

    @property
    def port(self) -> int:
        return int(self.listen.rpartition(":")[2])


class LoggingConfig(BaseModel):
    model_config = {"extra": "forbid"}

    level: str = "INFO"


class ExperimentConfig(BaseModel):
    """Phase 5 experiment-design controls.

    ``interleave_minutes`` > 0 enables the *time-interleaved* A/B design (spec
    §5b): the runner flips ``mode`` between vanilla and llm on that cadence so a
    single endpoint alternates arms over time (same IP/reputation). 0 disables it
    (use a fixed ``mode``, or the *parallel A/B* design — two stacks — instead).
    """

    model_config = {"extra": "forbid"}

    interleave_minutes: int = Field(default=0, ge=0)


class Config(BaseModel):
    """Top-level DeceptiNet-AI configuration (the ``deceptinet:`` block)."""

    model_config = {"extra": "forbid"}

    mode: Mode = "vanilla"
    experiment_id: str = "exp-000"
    services: ServicesConfig
    llm: LLMConfig = Field(default_factory=LLMConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    latency: LatencyConfig = Field(default_factory=LatencyConfig)
    containment: ContainmentConfig = Field(default_factory=ContainmentConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    datastore: DatastoreConfig = Field(default_factory=DatastoreConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    experiment: ExperimentConfig = Field(default_factory=ExperimentConfig)
