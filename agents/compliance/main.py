"""agents/compliance/main.py"""
from __future__ import annotations
import os, uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.logger          import get_logger
from core.tenant_registry import get_jurisdiction
from agents.compliance.graph import (
    build_compliance_graph_continuous,
    build_compliance_graph_report,
    ComplianceState,
)

logger = get_logger(__name__)
_graphs: dict = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    _graphs["continuous"]   = await build_compliance_graph_continuous()
    _graphs["board_report"] = await build_compliance_graph_report()
    logger.info("compliance_agent_ready")
    yield

app = FastAPI(title="SOC-COMPLIANCE-001", version="1.0.0", lifespan=lifespan)

class JobRequest(BaseModel):
    job_id:       str = ""
    tenant_id:    str
    department_id:str = ""
    mode:         str = "continuous"   # continuous | board_report | event_triggered
    framework_id: str = "ID_PDP_OJK"
    input:        dict = {}

@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SOC-COMPLIANCE-001"}

@app.post("/jobs")
async def run_job(req: JobRequest):
    job_id = req.job_id or str(uuid.uuid4())
    graph  = _graphs.get(req.mode, _graphs["continuous"])
    initial: ComplianceState = {
        "job_id":          job_id,
        "department_id":   req.department_id or f"soc-{req.tenant_id}",
        "tenant_id":       req.tenant_id,
        "jurisdiction":    get_jurisdiction(req.tenant_id),
        "mode":            req.mode,
        "messages":        [],
        "posture_data":    None,
        "framework_id":    req.framework_id,
        "gap_records":     [],
        "compliance_scores": None,
        "report_draft":    None,
        "quality_signal_emitted": False,
    }
    config = {"configurable": {"thread_id": job_id}}
    logger.info("job_started", extra={"job_id": job_id, "mode": req.mode})
    try:
        await graph.ainvoke(initial, config=config)
        snap  = await graph.aget_state(config)
        state = snap.values
        return {
            "status":            "complete" if req.mode == "continuous" else "hitl_pending",
            "job_id":            job_id,
            "compliance_scores": state.get("compliance_scores"),
            "gap_count":         len(state.get("gap_records", [])),
        }
    except Exception as e:
        logger.error("job_failed", extra={"job_id": job_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/webhook/correction")
async def correction(payload: dict):
    return {"status": "ok"}
