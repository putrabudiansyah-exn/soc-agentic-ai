"""
agents/remediation/graph.py — Remediation Agent.
Generates step-by-step IR playbooks. Tier 3: HITL before execution.
Step specificity enforced: every step >= 15 words.
"""

from __future__ import annotations
import json, operator, os, uuid
from datetime import datetime, timezone
from typing import Annotated
from typing_extensions import TypedDict

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph          import StateGraph, END
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from core.context_builder import build_system_prompt
from core.tenant_registry import get_tenant
from core.llm_client      import get_llm
from core.logger          import get_logger
from core.quality_signal  import QualitySignal, Check, Severity
from core.cost_tracker    import write_token_cost_event
from core.hitl_client     import submit_hitl_job

logger = get_logger(__name__)

INCIDENT_TYPE_MAP = {
    "ransomware_precursor":    "ransomware",
    "malware_detected":        "ransomware",
    "lateral_movement_attempt":"apt",
    "data_exfiltration":       "data_breach",
    "multiple_failed_logins":  "credential_compromise",
    "ddos_detected":           "ddos",
    "apt_indicator":           "apt",
}


# ── Playbook tracker (PostgreSQL-backed) ──────────────────────────────────────
async def save_playbook(job_id: str, tenant_id: str, playbook: dict) -> None:
    import asyncpg
    conn = await asyncpg.connect(os.getenv("POSTGRES_DSN"))
    await conn.execute(
        "INSERT INTO audit_log (job_id, tenant_id, agent_id, event_type, event_data) "
        "VALUES ($1,$2,$3,$4,$5)",
        job_id, tenant_id, "SOC-REMEDIATION-001",
        "playbook_created", json.dumps(playbook),
    )
    await conn.close()


# ── State ─────────────────────────────────────────────────────────────────────
class RemediationState(TypedDict):
    job_id:           str
    department_id:    str
    tenant_id:        str
    jurisdiction:     str
    incident_id:      str
    incident_context: dict
    tier:             int
    messages:         Annotated[list, operator.add]
    incident_type:    str | None
    playbook:         dict | None
    quality_signal_emitted: bool


# ── Nodes ─────────────────────────────────────────────────────────────────────

async def classify_incident_node(state: RemediationState) -> dict:
    ctx         = state["incident_context"]
    event_type  = ctx.get("event_type", "")
    ttps        = ctx.get("mitre_techniques", [])
    inc_type    = INCIDENT_TYPE_MAP.get(event_type, "unknown")
    if "T1486" in ttps or "T1490" in ttps: inc_type = "ransomware"
    if "T1041" in ttps and inc_type == "unknown": inc_type = "data_breach"
    logger.info("incident_classified", extra={
        "job_id": state["job_id"], "type": inc_type, "tier": state["tier"]
    })
    return {"incident_type": inc_type}


async def call_llm_node(state: RemediationState) -> dict:
    llm    = get_llm(temperature=0.15, max_tokens=2500)
    ctx    = state["incident_context"]
    prompt = (
        f"Generate an incident response playbook for a {state['incident_type']} incident.\n"
        f"Tier: {state['tier']} | Jurisdiction: {state['jurisdiction']}\n"
        f"Incident context: {json.dumps(ctx, indent=2)}\n\n"
        "Requirements:\n"
        "- Every step action must be >= 15 words and specific (name the tool, command, or system)\n"
        "- Include: containment, eradication, recovery, lessons_learned phases\n"
        "- Include evidence_to_preserve list\n"
        "- Include regulatory_obligations if incident type triggers reporting\n"
        "  (ID: BSSN 14d, OJK 24h if BFSI; MY: NACSA 24h; DE: BSI §30 24h)\n"
        "Return strict JSON only.\n\n"
        "Format:\n"
        '{\n  "incident_type": "...",\n  "tier": N,\n'
        '  "phases": [{"phase":"containment","steps":[{"step_id":"c-1","action":"...","responsible":"analyst","tooling":"...","estimated_duration_minutes":30,"status":"pending"}]}],\n'
        '  "evidence_to_preserve": ["..."],\n'
        '  "regulatory_obligations": ["..."],\n'
        '  "escalation_contacts": {"primary": "soc-lead@elitery.com"}\n}'
    )
    messages = state["messages"] + [HumanMessage(content=prompt)]
    response = await llm.ainvoke(messages)
    usage    = getattr(response, "usage_metadata", {}) or {}
    write_token_cost_event({
        "job_id": state["job_id"], "tenant_id": state["tenant_id"],
        "department_id": state["department_id"], "agent_id": "SOC-REMEDIATION-001",
        "model": "llama-3.3-70b", "node_name": "call_llm",
        "prompt_tokens": usage.get("input_tokens",0),
        "completion_tokens": usage.get("output_tokens",0), "cost_usd": 0.0,
    })
    return {"messages": [response]}


async def parse_playbook_node(state: RemediationState) -> dict:
    last = state["messages"][-1]
    try:
        content = str(last.content).strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"): content = content[4:]
        pb = json.loads(content.strip())
    except Exception as e:
        logger.warning("playbook_parse_failed", extra={"job_id": state["job_id"], "error": str(e)})
        pb = {
            "incident_type":        state.get("incident_type","unknown"),
            "tier":                 state["tier"],
            "phases":               [],
            "evidence_to_preserve": [],
            "regulatory_obligations":[],
            "escalation_contacts":  {},
            "_parse_error":         str(e),
        }
    pb["playbook_id"]   = str(uuid.uuid4())
    pb["incident_id"]   = state["incident_id"]
    pb["generated_at"]  = datetime.now(timezone.utc).isoformat()
    await save_playbook(state["job_id"], state["tenant_id"], pb)
    return {"playbook": pb}


async def emit_quality_signal_node(state: RemediationState) -> dict:
    pb   = state.get("playbook") or {}
    phases = pb.get("phases", [])
    all_steps = [s for ph in phases for s in ph.get("steps", [])]

    # Step specificity: all steps must be >= 15 words
    short_steps = [s for s in all_steps if len(s.get("action","").split()) < 15]
    has_containment = any(ph.get("phase") == "containment" for ph in phases)
    has_evidence    = bool(pb.get("evidence_to_preserve"))
    has_reg_obs     = isinstance(pb.get("regulatory_obligations"), list)
    has_contacts    = bool(pb.get("escalation_contacts"))
    inc_type        = state.get("incident_type","unknown")
    has_auditor_step= (inc_type in ("data_breach","ransomware") and
                       any("Auditor" in str(s.get("action","")) or
                           "BSSN" in str(s.get("action","")) or
                           "regulatory" in str(s.get("action","")).lower()
                           for s in all_steps))

    checks = [
        Check(check_id="incident_type_classified", name="Incident type determined",
              severity=Severity.HIGH, passed=inc_type != "unknown",
              message=f"type={inc_type}", field_path="incident_type"),
        Check(check_id="containment_steps_present", name="Containment phase has steps",
              severity=Severity.HIGH, passed=has_containment and bool(all_steps),
              message=f"containment={has_containment}, steps={len(all_steps)}", field_path="phases.containment"),
        Check(check_id="regulatory_obligations_identified", name="Regulatory obligations listed",
              severity=Severity.HIGH,
              passed=has_auditor_step or inc_type not in ("data_breach","ransomware"),
              message=f"inc_type={inc_type}, has_auditor_step={has_auditor_step}", field_path="phases"),
        Check(check_id="evidence_preservation_listed", name="Forensic evidence list present",
              severity=Severity.HIGH, passed=has_evidence,
              message=f"evidence_items={len(pb.get('evidence_to_preserve',[]))}", field_path="evidence_to_preserve"),
        Check(check_id="step_specificity_adequate", name="All steps >= 15 words",
              severity=Severity.MEDIUM, passed=len(short_steps)==0,
              expected=15, actual=min((len(s.get("action","").split()) for s in all_steps), default=0),
              delta=float(min((len(s.get("action","").split()) for s in all_steps), default=0) - 15),
              message=f"short_steps={len(short_steps)}", field_path="phases.*.steps.*.action"),
        Check(check_id="regulatory_deadlines_shown", name="Regulatory obligations list present",
              severity=Severity.MEDIUM, passed=has_reg_obs,
              field_path="regulatory_obligations"),
        Check(check_id="escalation_contacts_present", name="Escalation contacts included",
              severity=Severity.LOW, passed=has_contacts,
              field_path="escalation_contacts"),
    ]

    qs = QualitySignal(
        job_id  = state["job_id"],
        agent_id= "SOC-REMEDIATION-001",
        passed  = all(c.passed for c in checks if c.severity == Severity.HIGH),
        checks  = checks,
    )
    await qs.emit()
    logger.info("signal_emitted", extra={"job_id":state["job_id"],"passed":qs.passed,"tier":state["tier"]})
    return {"quality_signal_emitted": True, "_qs_passed": qs.passed}


async def finalize_playbook_node(state: RemediationState) -> dict:
    """Tier 3: runs only after analyst approves via interrupt_before."""
    logger.info("playbook_approved", extra={
        "job_id": state["job_id"], "tier": state["tier"]
    })
    return {}


# ── Graph ─────────────────────────────────────────────────────────────────────

async def build_remediation_graph():
    gb = StateGraph(RemediationState)
    gb.add_node("classify_incident",   classify_incident_node)
    gb.add_node("build_context",       _build_context_node)
    gb.add_node("call_llm",            call_llm_node)
    gb.add_node("parse_playbook",      parse_playbook_node)
    gb.add_node("emit_quality_signal", emit_quality_signal_node)
    gb.add_node("finalize_playbook",   finalize_playbook_node)

    gb.set_entry_point("classify_incident")
    gb.add_edge("classify_incident",   "build_context")
    gb.add_edge("build_context",       "call_llm")
    gb.add_edge("call_llm",            "parse_playbook")
    gb.add_edge("parse_playbook",      "emit_quality_signal")
    gb.add_edge("emit_quality_signal", "finalize_playbook")
    gb.add_edge("finalize_playbook",   END)

    dsn         = os.getenv("POSTGRES_DSN")
    checkpointer= await AsyncPostgresSaver.from_conn_string(dsn)
    await checkpointer.setup()

    return gb.compile(
        checkpointer    = checkpointer,
        interrupt_before= ["finalize_playbook"],   # Tier 3 requires analyst approval
    )

async def _build_context_node(state: RemediationState) -> dict:
    tenant = get_tenant(state["tenant_id"])
    sp     = build_system_prompt(tenant, "remediation")
    return {"messages": [SystemMessage(content=sp)]}
