"""
core/hitl_client.py — LIGHTWEIGHT SHIM

Submits HITL jobs to the lightweight FastAPI review UI.
At SAO migration, this shim is REMOVED entirely — SAO reads the
Quality Signal passed field and routes automatically via interrupt_before.

  BEFORE: from core.hitl_client import submit_hitl_job
  AFTER:  (remove import — SAO handles routing from QS.passed)

The interrupt_before pattern in LangGraph stays unchanged.
"""

from __future__ import annotations
import os
import httpx


async def submit_hitl_job(
    job_id:       str,
    agent_id:     str,
    tenant_id:    str,
    jurisdiction: str,
    draft:        dict,
    qs_payload:   dict,
    reviewer_role: str = "analyst",
    timeout_minutes: int = 30,
) -> None:
    """
    Post job to lightweight HITL review queue.
    Analysts review at http://localhost:8090/hitl/review/{job_id}

    SAO migration: remove this call entirely.
    interrupt_before=["route_result"] already suspends the graph.
    SAO HITL dashboard picks up suspended jobs automatically.
    """
    hitl_url = os.getenv("HITL_UI_URL", "http://localhost:8090")
    payload = {
        "job_id":          job_id,
        "agent_id":        agent_id,
        "tenant_id":       tenant_id,
        "jurisdiction":    jurisdiction,
        "draft":           draft,
        "quality_signal":  qs_payload,
        "reviewer_role":   reviewer_role,
        "timeout_minutes": timeout_minutes,
    }
    async with httpx.AsyncClient(timeout=10.0) as c:
        resp = await c.post(f"{hitl_url}/hitl/jobs", json=payload)
        resp.raise_for_status()


async def get_hitl_decision(job_id: str) -> dict | None:
    """
    Poll for analyst decision.
    Returns: {"decision": "APPROVE"|"REJECT"|"ESCALATE", "reviewer_id": "...", "notes": "..."}
    Returns None if still pending.
    """
    hitl_url = os.getenv("HITL_UI_URL", "http://localhost:8090")
    async with httpx.AsyncClient(timeout=5.0) as c:
        resp = await c.get(f"{hitl_url}/hitl/jobs/{job_id}/decision")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        return data if data.get("decision") else None
