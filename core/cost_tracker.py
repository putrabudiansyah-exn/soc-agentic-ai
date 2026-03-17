"""
core/cost_tracker.py — LIGHTWEIGHT SHIM

Writes token cost events directly to ClickHouse token_events table.
Same schema the SAO SDK uses — zero data migration at swap.

  BEFORE: from core.cost_tracker import write_token_cost_event
  AFTER:  from sao_sdk.cost       import write_token_cost_event

Nothing else changes.
"""

from __future__ import annotations
import os
from datetime import datetime, timezone

import clickhouse_connect


def write_token_cost_event(event: dict) -> None:
    """
    Synchronous write to ClickHouse token_events table.
    SAO SDK equivalent: await sao_sdk.cost.write_token_cost_event(event)

    Required fields:
        job_id, tenant_id, department_id, agent_id,
        model, node_name, prompt_tokens, completion_tokens, cost_usd
    """
    client = _get_client()
    row = [
        event["job_id"],
        event["tenant_id"],
        event["department_id"],
        event["agent_id"],
        event["model"],
        event["node_name"],
        int(event.get("prompt_tokens", 0)),
        int(event.get("completion_tokens", 0)),
        float(event.get("cost_usd", 0.0)),
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    ]
    client.insert(
        "token_events",
        [row],
        column_names=[
            "job_id", "tenant_id", "department_id", "agent_id",
            "model", "node_name", "prompt_tokens", "completion_tokens",
            "cost_usd", "recorded_at",
        ],
    )


def _get_client():
    url = os.getenv("CLICKHOUSE_URL", "http://localhost:8123")
    db  = os.getenv("CLICKHOUSE_DB",  "soc_metrics")
    return clickhouse_connect.get_client(
        host=url.replace("http://", "").split(":")[0],
        port=int(url.split(":")[-1]),
        database=db,
    )
