"""
core/quality_signal.py — LIGHTWEIGHT SHIM

Writes Quality Signal JSON to PostgreSQL quality_signals table.
Implements the same interface as sao_sdk.quality so migration is
a single import swap:

  BEFORE: from core.quality_signal import QualitySignal, Check, Severity
  AFTER:  from sao_sdk.quality       import QualitySignal, Check, Severity

Nothing else changes in agent code.
"""

from __future__ import annotations
import asyncio, json, os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import asyncpg


class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class Check:
    check_id:   str
    name:       str
    severity:   Severity
    passed:     bool
    expected:   Any    = None
    actual:     Any    = None
    delta:      float  | None = None
    message:    str    = ""
    field_path: str    = ""

    def to_dict(self) -> dict:
        return {
            "check_id":   self.check_id,
            "name":       self.name,
            "severity":   self.severity.value,
            "passed":     self.passed,
            "expected":   self.expected,
            "actual":     self.actual,
            "delta":      self.delta,
            "message":    self.message,
            "field_path": self.field_path,
        }


@dataclass
class QualitySignal:
    job_id:     str
    agent_id:   str
    passed:     bool
    checks:     list[Check]
    confidence: dict[str, float] = field(default_factory=dict)
    metadata:   dict             = field(default_factory=dict)
    checked_at: str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    async def emit(self) -> None:
        """Write Quality Signal to PostgreSQL. Swap to sao_sdk.quality at migration."""
        payload = {
            "job_id":     self.job_id,
            "agent_id":   self.agent_id,
            "checked_at": self.checked_at,
            "passed":     self.passed,
            "checks":     [c.to_dict() for c in self.checks],
            "confidence": self.confidence,
            "metadata":   self.metadata,
        }

        dsn = os.getenv("POSTGRES_DSN")
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(
                """
                INSERT INTO quality_signals
                    (job_id, agent_id, checked_at, passed, payload)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (job_id) DO UPDATE
                SET checked_at = $3, passed = $4, payload = $5
                """,
                self.job_id,
                self.agent_id,
                self.checked_at,
                self.passed,
                json.dumps(payload),
            )
        finally:
            await conn.close()

        # HITL routing: if not passed, notify lightweight HITL UI
        if not self.passed:
            await _notify_hitl(self.job_id, payload)

    @property
    def failed_high_checks(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and c.severity == Severity.HIGH]


async def _notify_hitl(job_id: str, qs_payload: dict) -> None:
    """Notify lightweight HITL UI. Removed at migration — SAO reads QS.passed directly."""
    import httpx
    hitl_url = os.getenv("HITL_UI_URL", "http://localhost:8090")
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(f"{hitl_url}/hitl/queue", json={
                "job_id":    job_id,
                "qs_passed": qs_payload["passed"],
                "qs":        qs_payload,
            })
    except Exception as e:
        # Non-fatal: HITL UI may not be up in test environments
        import logging
        logging.getLogger(__name__).warning("HITL notify failed: %s", e)
