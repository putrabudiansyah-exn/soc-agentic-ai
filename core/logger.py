"""
core/logger.py — LIGHTWEIGHT SHIM

Structured JSON logger to stdout. Compatible with any log aggregator.

  BEFORE: from core.logger    import get_logger
  AFTER:  from sao_sdk.logging import get_logger

Function signature identical. Migration is one import change per file.
"""

from __future__ import annotations
import json
import logging
import os
import sys
from datetime import datetime, timezone


class _StructuredFormatter(logging.Formatter):
    def __init__(self, agent_id: str = "", tenant_id: str = ""):
        super().__init__()
        self._agent_id  = agent_id
        self._tenant_id = tenant_id

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
            "agent_id":  self._agent_id,
        }
        # Merge extra fields
        for k, v in record.__dict__.items():
            if k not in logging.LogRecord.__dict__ and not k.startswith("_"):
                base[k] = v
        return json.dumps(base, default=str)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a structured JSON logger.
    SAO SDK equivalent: sao_sdk.logging.get_logger(name)
    Both return a standard logging.Logger with the same interface.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_StructuredFormatter(
        agent_id  = os.getenv("AGENT_ID", "unknown"),
        tenant_id = os.getenv("CURRENT_TENANT_ID", ""),
    ))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
