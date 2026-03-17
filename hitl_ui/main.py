"""
hitl_ui/main.py — Lightweight HITL review UI.
Decommissioned at SAO migration (SAO HITL dashboard takes over).
"""

from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

DSN = os.getenv("POSTGRES_DSN", "postgresql://soc:soc@localhost:5432/socdev")
_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    _pool = await asyncpg.create_pool(DSN, min_size=2, max_size=10)
    yield
    await _pool.close()

app       = FastAPI(title="SOC Pod HITL UI", lifespan=lifespan)
templates = Jinja2Templates(directory="/app/templates")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "hitl-ui"}


# ── Queue management ──────────────────────────────────────────────────────────

@app.post("/hitl/jobs")
async def submit_hitl_job(payload: dict):
    """Receive HITL job from agent (via hitl_client.py shim)."""
    job_id  = payload["job_id"]
    timeout = payload.get("timeout_minutes", 30)
    timeout_at = datetime.now(timezone.utc) + timedelta(minutes=timeout)
    content_hash = hashlib.sha256(
        json.dumps(payload.get("draft", {}), sort_keys=True).encode()
    ).hexdigest()

    async with _pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO hitl_queue
              (job_id, agent_id, tenant_id, jurisdiction, reviewer_role,
               draft, quality_signal, timeout_at, content_hash)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (job_id) DO NOTHING
            """,
            job_id,
            payload.get("agent_id",      "SOC-TRIAGE-001"),
            payload.get("tenant_id",     ""),
            payload.get("jurisdiction",  ""),
            payload.get("reviewer_role", "analyst"),
            json.dumps(payload.get("draft",           {})),
            json.dumps(payload.get("quality_signal",  {})),
            timeout_at,
            content_hash,
        )
    return {"status": "queued", "job_id": job_id}


@app.post("/hitl/queue")
async def notify_hitl_queue(payload: dict):
    """Notification from quality_signal shim that a job needs HITL."""
    # job may already be in queue from submit_hitl_job; this is a no-op if so
    return {"status": "acknowledged"}


@app.get("/hitl/jobs/{job_id}/decision")
async def get_decision(job_id: str):
    """Poll for analyst decision. Returns 404 while pending."""
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT decision, reviewer_id, reviewer_notes, content_hash "
            "FROM hitl_queue WHERE job_id=$1", job_id
        )
    if not row or not row["decision"]:
        raise HTTPException(status_code=404, detail="No decision yet")
    return {
        "decision":       row["decision"],
        "reviewer_id":    row["reviewer_id"],
        "notes":          row["reviewer_notes"],
        "content_hash":   row["content_hash"],
    }


@app.get("/hitl/pending")
async def list_pending():
    """List all pending HITL jobs (for dashboard)."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT job_id, agent_id, tenant_id, jurisdiction,
                   submitted_at, timeout_at, content_hash
            FROM hitl_queue
            WHERE decision IS NULL
            ORDER BY submitted_at ASC
            """
        )
    return [dict(r) for r in rows]


# ── Review UI ─────────────────────────────────────────────────────────────────

@app.get("/hitl/review/{job_id}", response_class=HTMLResponse)
async def review_page(request: Request, job_id: str):
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM hitl_queue WHERE job_id=$1", job_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    draft = json.loads(row["draft"])
    qs    = json.loads(row["quality_signal"])
    now   = datetime.now(timezone.utc)
    timeout_at = row["timeout_at"]
    minutes_left = max(0, int((timeout_at - now).total_seconds() / 60)) if timeout_at else 0

    return templates.TemplateResponse("review.html", {
        "request":      request,
        "job_id":       job_id,
        "agent_id":     row["agent_id"],
        "tenant_id":    row["tenant_id"],
        "jurisdiction": row["jurisdiction"],
        "draft":        draft,
        "qs":           qs,
        "minutes_left": minutes_left,
        "submitted_at": row["submitted_at"],
        "draft_pretty": json.dumps(draft, indent=2),
        "qs_pretty":    json.dumps(qs,    indent=2),
    })


@app.post("/hitl/review/{job_id}/decide")
async def submit_decision(job_id: str, payload: dict):
    """Analyst submits APPROVE / REJECT / ESCALATE."""
    decision    = payload.get("decision", "").upper()
    reviewer_id = payload.get("reviewer_id", "analyst")
    notes       = payload.get("notes", "")

    if decision not in ("APPROVE", "REJECT", "ESCALATE"):
        raise HTTPException(status_code=400, detail="decision must be APPROVE|REJECT|ESCALATE")

    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT job_id, draft, tenant_id, agent_id FROM hitl_queue WHERE job_id=$1",
            job_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Job not found")

        # Compute hash of draft at time of approval (audit trail)
        draft = json.loads(row["draft"])
        content_hash = hashlib.sha256(
            json.dumps(draft, sort_keys=True).encode()
        ).hexdigest()

        await conn.execute(
            """
            UPDATE hitl_queue
            SET decision=$1, reviewer_id=$2, reviewer_notes=$3,
                resolved_at=NOW(), content_hash=$4
            WHERE job_id=$5
            """,
            decision, reviewer_id, notes, content_hash, job_id,
        )

        # Write to immutable audit log
        await conn.execute(
            """
            INSERT INTO audit_log (job_id, tenant_id, agent_id, event_type, event_data)
            VALUES ($1,$2,$3,$4,$5)
            """,
            job_id, row["tenant_id"], row["agent_id"],
            "hitl_decision",
            json.dumps({
                "decision":     decision,
                "reviewer_id":  reviewer_id,
                "notes":        notes,
                "content_hash": content_hash,
                "resolved_at":  datetime.now(timezone.utc).isoformat(),
            }),
        )

    return {"status": "ok", "job_id": job_id, "decision": decision}


# ── Dashboard (simple) ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    async with _pool.acquire() as conn:
        pending = await conn.fetch(
            "SELECT job_id, agent_id, tenant_id, jurisdiction, submitted_at "
            "FROM hitl_queue WHERE decision IS NULL ORDER BY submitted_at ASC"
        )
        recent = await conn.fetch(
            "SELECT job_id, agent_id, tenant_id, decision, reviewer_id, resolved_at "
            "FROM hitl_queue WHERE decision IS NOT NULL "
            "ORDER BY resolved_at DESC LIMIT 20"
        )
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "pending": [dict(r) for r in pending],
        "recent":  [dict(r) for r in recent],
    })
