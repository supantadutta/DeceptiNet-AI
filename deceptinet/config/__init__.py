"""Configuration layer: single source of truth for DeceptiNet-AI.

Everything reads from a validated :class:`~deceptinet.config.models.Config`
object loaded from ``config.yaml`` (env-var overridable). See spec §4.
"""

from deceptinet.config.loader import load_config
from deceptinet.config.models import Config

__all__ = ["Config", "load_config"]
