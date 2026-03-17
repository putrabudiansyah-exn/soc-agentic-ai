"""
agents/triage/main.py — FastAPI app for the Triage Agent.

SAO migration change: accept job_id from SAO payload (it's already present).
No other changes needed.
"""

from __future__ import annotations
import json, os, uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.logger           import get_logger
from core.tenant_registry  import get_jurisdiction
from agents.triage.graph   import build_triage_graph, TriageState

logger = get_logger(__name__)
_graph = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _graph
    logger.info("triage_agent_starting")
    _graph = await build_triage_graph()
    logger.info("triage_agent_ready")
    yield
    logger.info("triage_agent_stopping")


app = FastAPI(title="SOC-TRIAGE-001", version="1.0.0", lifespan=lifespan)


class JobRequest(BaseModel):
    job_id:       str = ""     # SAO provides this; lightweight stack self-generates
    agent_id:     str = "SOC-TRIAGE-001"
    tenant_id:    str
    department_id:str = ""
    input:        dict


def _sanitise_event(event: dict) -> dict:
    """Strip free-text fields that could carry prompt injection."""
    BLOCKED = {"raw_log", "full_log", "message_raw", "original_log", "syslog_raw"}
    return {k: v for k, v in event.items() if k not in BLOCKED}


@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SOC-TRIAGE-001"}


@app.post("/jobs")
async def run_job(req: JobRequest):
    job_id = req.job_id or str(uuid.uuid4())
    dept   = req.department_id or f"soc-{req.tenant_id}"

    initial_state: TriageState = {
        "job_id":         job_id,
        "department_id":  dept,
        "tenant_id":      req.tenant_id,
        "jurisdiction":   get_jurisdiction(req.tenant_id),
        "event":          _sanitise_event(req.input),
        "messages":       [],
        "tool_call_count":0,
        "opa_denials":    0,
        "budget_status":  "OK",
        "_retry_count":   0,
        "assessment":     None,
        "tier":           None,
        "tier_rationale": None,
        "hitl_required":  False,
        "auto_resolved":  False,
        "quality_signal_emitted": False,
    }

    config = {"configurable": {"thread_id": job_id}}

    logger.info("job_started", extra={
        "job_id":     job_id,
        "tenant_id":  req.tenant_id,
        "event_type": req.input.get("event_type"),
        "event_id":   req.input.get("event_id"),
    })

    try:
        await _graph.ainvoke(initial_state, config=config)
        # Retrieve final state from checkpoint
        snapshot = await _graph.aget_state(config)
        state    = snapshot.values
        logger.info("job_complete", extra={
            "job_id":       job_id,
            "tier":         state.get("tier"),
            "hitl_required":state.get("hitl_required"),
            "auto_resolved":state.get("auto_resolved"),
        })
        return {
            "status":        "complete",
            "job_id":        job_id,
            "tier":          state.get("tier"),
            "tier_rationale":state.get("tier_rationale"),
            "hitl_required": state.get("hitl_required"),
            "auto_resolved": state.get("auto_resolved"),
            "assessment":    state.get("assessment"),
        }
    except Exception as e:
        logger.error("job_failed", extra={"job_id": job_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhook/correction")
async def correction_webhook(payload: dict):
    """
    Called by lightweight HITL UI (or SAO at migration) when analyst modifies output.
    Logs correction to audit trail.
    """
    job_id = payload.get("job_id", "unknown")
    logger.info("correction_received", extra={
        "job_id":      job_id,
        "field":       payload.get("field"),
        "was_changed": payload.get("was_changed"),
        "change_type": payload.get("change_type"),
        "reviewer_id": payload.get("reviewer_id"),
    })
    # Store correction in audit_log table
    import asyncpg
    conn = await asyncpg.connect(os.getenv("POSTGRES_DSN"))
    await conn.execute(
        "INSERT INTO audit_log (job_id, tenant_id, agent_id, event_type, event_data) "
        "VALUES ($1, $2, $3, $4, $5)",
        job_id, payload.get("tenant_id",""), "SOC-TRIAGE-001",
        "correction", json.dumps(payload),
    )
    await conn.close()
    return {"status": "ok"}
