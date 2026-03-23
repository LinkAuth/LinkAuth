"""Structured logging setup using structlog.

Two simultaneous outputs from the same event pipeline:
- Console (stdout): colored, human-readable for Docker/Coolify logs
- JSON file: machine-readable with log rotation for analysis
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import structlog

from broker.config import LoggingConfig


def setup_logging(config: LoggingConfig) -> None:
    """Configure structlog + stdlib logging with dual output."""

    log_level = getattr(logging, config.level.upper(), logging.INFO)

    # Shared structlog pre-processing (runs before stdlib formatting)
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Console formatter — colored key=value output
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        foreign_pre_chain=shared_processors,
    )

    # JSON formatter — machine-readable JSONL
    json_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    # Handler 1: Console (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)

    # Handler 2: JSON file with rotation
    log_dir = os.path.dirname(config.json_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        config.json_file,
        maxBytes=config.max_bytes,
        backupCount=config.backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(json_formatter)
    file_handler.setLevel(log_level)

    # Configure root logger
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(console_handler)
    root.addHandler(file_handler)
    root.setLevel(log_level)

    # Tame noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    # Configure structlog to use stdlib as backend
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
