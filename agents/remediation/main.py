"""agents/remediation/main.py"""
from __future__ import annotations
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.logger          import get_logger
from core.tenant_registry import get_jurisdiction
from agents.remediation.graph import build_remediation_graph, RemediationState

logger = get_logger(__name__)
_graph = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _graph
    _graph = await build_remediation_graph()
    logger.info("remediation_agent_ready")
    yield

app = FastAPI(title="SOC-REMEDIATION-001", version="1.0.0", lifespan=lifespan)

class JobRequest(BaseModel):
    job_id:           str = ""
    tenant_id:        str
    department_id:    str = ""
    incident_id:      str = ""
    tier:             int = 2
    incident_context: dict = {}
    input:            dict = {}

@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SOC-REMEDIATION-001"}

@app.post("/jobs")
async def run_job(req: JobRequest):
    job_id = req.job_id or str(uuid.uuid4())
    ctx    = req.incident_context or req.input
    initial: RemediationState = {
        "job_id":           job_id,
        "department_id":    req.department_id or f"soc-{req.tenant_id}",
        "tenant_id":        req.tenant_id,
        "jurisdiction":     get_jurisdiction(req.tenant_id),
        "incident_id":      req.incident_id or job_id,
        "incident_context": ctx,
        "tier":             req.tier,
        "messages":         [],
        "incident_type":    None,
        "playbook":         None,
        "quality_signal_emitted": False,
    }
    config = {"configurable": {"thread_id": job_id}}
    logger.info("job_started", extra={"job_id": job_id, "tier": req.tier})
    try:
        await _graph.ainvoke(initial, config=config)
        snap  = await _graph.aget_state(config)
        state = snap.values
        return {
            "status":        "hitl_pending" if req.tier >= 3 else "complete",
            "job_id":        job_id,
            "incident_type": state.get("incident_type"),
            "playbook_id":   (state.get("playbook") or {}).get("playbook_id"),
        }
    except Exception as e:
        logger.error("job_failed", extra={"job_id": job_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/webhook/correction")
async def correction(payload: dict):
    return {"status": "ok"}
