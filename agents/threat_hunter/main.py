"""agents/threat_hunter/main.py"""
from __future__ import annotations
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.logger          import get_logger
from core.tenant_registry import get_jurisdiction
from agents.threat_hunter.graph import (
    build_hunter_graph_weekly, build_hunter_graph_quarterly, ThreatHunterState
)

logger = get_logger(__name__)
_graphs: dict = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    _graphs["weekly_scan"]      = await build_hunter_graph_weekly()
    _graphs["quarterly_report"] = await build_hunter_graph_quarterly()
    logger.info("threat_hunter_ready")
    yield

app = FastAPI(title="SOC-HUNTER-001", version="1.0.0", lifespan=lifespan)

class JobRequest(BaseModel):
    job_id:       str = ""
    tenant_id:    str
    department_id:str = ""
    mode:         str = "weekly_scan"
    input:        dict = {}

@app.get("/health")
async def health():
    return {"status": "ok", "agent": "SOC-HUNTER-001"}

@app.post("/jobs")
async def run_job(req: JobRequest):
    job_id = req.job_id or str(uuid.uuid4())
    graph  = _graphs.get(req.mode, _graphs["weekly_scan"])
    initial: ThreatHunterState = {
        "job_id":              job_id,
        "department_id":       req.department_id or f"soc-{req.tenant_id}",
        "tenant_id":           req.tenant_id,
        "jurisdiction":        get_jurisdiction(req.tenant_id),
        "mode":                req.mode,
        "messages":            [],
        "asset_scores":        None,
        "attack_paths":        [],
        "top_vulnerabilities": [],
        "overall_score":       None,
        "report_draft":        None,
        "quality_signal_emitted": False,
    }
    config = {"configurable": {"thread_id": job_id}}
    logger.info("job_started", extra={"job_id": job_id, "mode": req.mode})
    try:
        await graph.ainvoke(initial, config=config)
        snap  = await graph.aget_state(config)
        state = snap.values
        return {
            "status":        "hitl_pending" if req.mode == "quarterly_report" else "complete",
            "job_id":        job_id,
            "overall_score": state.get("overall_score"),
            "attack_paths":  len(state.get("attack_paths",[])),
            "assets_scored": len(state.get("asset_scores",{})),
        }
    except Exception as e:
        logger.error("job_failed", extra={"job_id": job_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/webhook/correction")
async def correction(payload: dict):
    return {"status": "ok"}
