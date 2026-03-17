"""agents/auditor/main.py — Auditor Agent FastAPI entrypoint."""
from __future__ import annotations
import json, os, uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.logger          import get_logger
from core.tenant_registry import get_jurisdiction
from agents.auditor.graph import build_auditor_graph, AuditorState

logger = get_logger(__name__)
_graph = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _graph
    _graph = await build_auditor_graph()
    logger.info("auditor_agent_ready")
    yield

app = FastAPI(title="SOC-AUDITOR-001", version="1.0.0", lifespan=lifespan)

class JobRequest(BaseModel):
    job_id:           str = ""
    tenant_id:        str
    department_id:    str = ""
    incident_id:      str = ""
    incident_context: dict = {}
    input:            dict = {}   # alternative to incident_context

@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SOC-AUDITOR-001"}

@app.post("/jobs")
async def run_job(req: JobRequest):
    job_id  = req.job_id or str(uuid.uuid4())
    ctx     = req.incident_context or req.input
    initial: AuditorState = {
        "job_id":           job_id,
        "department_id":    req.department_id or f"soc-{req.tenant_id}",
        "tenant_id":        req.tenant_id,
        "jurisdiction":     get_jurisdiction(req.tenant_id),
        "incident_id":      req.incident_id or ctx.get("incident_id", job_id),
        "incident_context": ctx,
        "messages":         [],
        "filing_type":      None,
        "draft_content":    None,
        "gaps":             [],
        "faithfulness_score": None,
        "deadline_utc":     None,
        "quality_signal_emitted": False,
    }
    config = {"configurable": {"thread_id": job_id}}
    logger.info("job_started", extra={"job_id": job_id, "tenant_id": req.tenant_id})
    try:
        await _graph.ainvoke(initial, config=config)
        snap  = await _graph.aget_state(config)
        state = snap.values
        return {
            "status":       "hitl_pending",
            "job_id":       job_id,
            "filing_type":  state.get("filing_type"),
            "deadline_utc": state.get("deadline_utc"),
            "gaps":         state.get("gaps", []),
        }
    except Exception as e:
        logger.error("job_failed", extra={"job_id": job_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/webhook/correction")
async def correction(payload: dict):
    logger.info("correction_received", extra=payload)
    return {"status": "ok"}
