"""``python -m deceptinet`` — load config, configure logging, run the app."""

from __future__ import annotations

import asyncio
import sys

from deceptinet.config.loader import load_config
from deceptinet.logging_setup import configure_logging, get_logger
from deceptinet.runner import run


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    config_path = argv[0] if argv else None
    try:
        config = load_config(config_path)
    except Exception as exc:  # config errors should be readable, not tracebacks
        # Logging may not be configured yet; print plainly to stderr.
        print(f"deceptinet: configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.logging.level)
    log = get_logger("deceptinet")
    log.info(
        "starting DeceptiNet-AI",
        extra={"mode": config.mode, "experiment_id": config.experiment_id,
               "event": "boot"},
    )
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:  # pragma: no cover
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
