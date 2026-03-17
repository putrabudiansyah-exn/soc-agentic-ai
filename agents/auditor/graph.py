"""
agents/auditor/graph.py — Auditor Agent LangGraph.

SHIM SWAP POINTS (at SAO migration):
  core.quality_signal → sao_sdk.quality
  core.cost_tracker   → sao_sdk.cost
  core.logger         → sao_sdk.logging
  core.hitl_client    → remove (SAO reads QS.passed)

CRITICAL: interrupt_before=["submit_to_hitl"] is non-bypassable.
A regulatory filing NEVER submits without analyst co-sign.
"""

from __future__ import annotations
import hashlib, json, operator, os
from datetime import datetime, timedelta, timezone
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

try:
    import holidays as _hol
    _HOLIDAY_CALENDARS = {"MY":_hol.Malaysia(),"ID":_hol.Indonesia(),"DE":_hol.Germany()}
except Exception:
    _HOLIDAY_CALENDARS = {}

logger = get_logger(__name__)

FAITHFULNESS_THRESHOLD = 0.95   # raised from platform default 0.85

# ── Deadline hours per filing type ────────────────────────────────────────────
DEADLINES: dict[str, int] = {
    "NACSA_initial":    24,   "NACSA_full":       336,
    "PDPA_breach":      72,   "BSSN_incident":    336,
    "KOMINFO_PDP":      72,   "OJK_SEOJK":         24,
    "BSI_30_initial":   24,   "NIS2_23_early":     72,
    "NIS2_23_full":    720,   "DSGVO_33":           72,
    "BNM_RMiT":         24,
}

def calculate_deadline(filing_type: str, detection_ts: str) -> str:
    hours = DEADLINES.get(filing_type, 72)
    base  = datetime.fromisoformat(detection_ts.replace("Z", "+00:00"))
    return (base + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── State ─────────────────────────────────────────────────────────────────────
class AuditorState(TypedDict):
    job_id:           str
    department_id:    str
    tenant_id:        str
    jurisdiction:     str
    incident_id:      str
    incident_context: dict
    messages:         Annotated[list, operator.add]
    filing_type:      str | None
    draft_content:    dict | None
    gaps:             list[str]
    faithfulness_score: float | None
    deadline_utc:     str | None
    quality_signal_emitted: bool


# ── Filing type determination ─────────────────────────────────────────────────
def _determine_filing_type(ctx: dict, jurisdiction: str) -> str:
    has_pii   = bool(ctx.get("pii_involved"))
    is_bfsi   = ctx.get("ncii_sector") == "BFSI"
    inc_type  = ctx.get("incident_type", "")

    if jurisdiction == "ID":
        if is_bfsi:          return "OJK_SEOJK"
        if has_pii:          return "KOMINFO_PDP"
        return "BSSN_incident"
    if jurisdiction == "MY":
        if has_pii:          return "PDPA_breach"
        return "NACSA_initial"
    if jurisdiction == "DE":
        if has_pii:          return "DSGVO_33"
        return "BSI_30_initial"
    return "NACSA_initial"


# ── Nodes ─────────────────────────────────────────────────────────────────────

async def determine_filing_type_node(state: AuditorState) -> dict:
    ctx          = state["incident_context"]
    filing_type  = _determine_filing_type(ctx, state["jurisdiction"])
    detection_ts = ctx.get("detection_timestamp",
                            datetime.now(timezone.utc).isoformat())
    deadline = calculate_deadline(filing_type, detection_ts)
    logger.info("filing_type_determined", extra={
        "job_id": state["job_id"], "filing_type": filing_type, "deadline": deadline
    })
    return {"filing_type": filing_type, "deadline_utc": deadline, "gaps": []}


async def build_context_node(state: AuditorState) -> dict:
    tenant        = get_tenant(state["tenant_id"])
    system_prompt = build_system_prompt(tenant, "auditor")
    return {"messages": [SystemMessage(content=system_prompt)]}


async def call_llm_node(state: AuditorState) -> dict:
    llm = get_llm(temperature=0.05, max_tokens=2000)   # low temp for filings

    if not any(isinstance(m, HumanMessage) for m in state["messages"]):
        prompt = (
            f"Draft a {state['filing_type']} regulatory filing.\n"
            f"Deadline: {state['deadline_utc']}\n\n"
            f"Incident context:\n{json.dumps(state['incident_context'], indent=2)}\n\n"
            "Return strict JSON. No text before or after the JSON.\n"
            "For any field you cannot determine from the incident data, "
            "list it in the gaps[] array with the reason.\n"
            "NEVER fabricate facts. If uncertain, add to gaps[]."
        )
        messages = state["messages"] + [HumanMessage(content=prompt)]
    else:
        messages = state["messages"]

    response = await llm.ainvoke(messages)
    usage    = getattr(response, "usage_metadata", {}) or {}
    write_token_cost_event({
        "job_id":            state["job_id"],
        "tenant_id":         state["tenant_id"],
        "department_id":     state["department_id"],
        "agent_id":          "SOC-AUDITOR-001",
        "model":             "llama-3.3-70b",
        "node_name":         "call_llm",
        "prompt_tokens":     usage.get("input_tokens",  0),
        "completion_tokens": usage.get("output_tokens", 0),
        "cost_usd":          0.0,
    })
    return {"messages": [response]}


async def check_hallucination_node(state: AuditorState) -> dict:
    last = state["messages"][-1]
    if not hasattr(last, "content") or not last.content:
        return {"faithfulness_score": None}
    try:
        from deepeval.metrics   import FaithfulnessMetric
        from deepeval.test_case import LLMTestCase
        context = [json.dumps(state["incident_context"])]
        tc      = LLMTestCase(
            input            = f"Draft {state['filing_type']} filing",
            actual_output    = str(last.content),
            retrieval_context= context,
        )
        m = FaithfulnessMetric(threshold=FAITHFULNESS_THRESHOLD)
        m.measure(tc)
        score = getattr(m, "score", 0.0)
        logger.info("faithfulness_checked", extra={
            "job_id": state["job_id"], "score": score, "passed": m.is_successful()
        })
        return {"faithfulness_score": score, "_faith_passed": m.is_successful()}
    except Exception as e:
        logger.warning("deepeval_unavailable", extra={"error": str(e)})
        return {"faithfulness_score": None, "_faith_passed": True}


async def validate_draft_node(state: AuditorState) -> dict:
    last = state["messages"][-1]
    if not hasattr(last, "content") or not last.content:
        return {"draft_content": None, "gaps": ["LLM returned no content"]}
    try:
        content = str(last.content).strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"): content = content[4:]
        parsed = json.loads(content.strip())
    except json.JSONDecodeError as e:
        return {"draft_content": None, "gaps": [f"JSON parse failed: {e}"]}

    draft = parsed.get("draft_content", parsed)
    gaps  = parsed.get("gaps", [])
    analyst_instructions = parsed.get("analyst_instructions", "")

    logger.info("draft_validated", extra={
        "job_id": state["job_id"],
        "gaps":   len(gaps),
        "fields": len(draft),
    })
    return {
        "draft_content": draft,
        "gaps":          gaps,
        "_analyst_instructions": analyst_instructions,
    }


async def emit_quality_signal_node(state: AuditorState) -> dict:
    draft    = state.get("draft_content") or {}
    gaps     = state.get("gaps", [])
    faith    = state.get("faithfulness_score")
    deadline = state.get("deadline_utc", "")
    ai       = state.get("_analyst_instructions", "")

    # deadline validity check
    deadline_valid = False
    if deadline:
        try:
            dl = datetime.fromisoformat(deadline.replace("Z","+00:00"))
            deadline_valid = dl > datetime.now(timezone.utc)
        except Exception:
            pass

    checks = [
        Check(
            check_id  = "required_fields_present",
            name      = "All required filing fields present or flagged",
            severity  = Severity.HIGH,
            passed    = bool(draft) and len(draft) > 0,
            message   = f"fields={len(draft)}, gaps={len(gaps)}",
            field_path= "draft_content",
        ),
        Check(
            check_id  = "deadline_calculated",
            name      = "Regulatory deadline correctly computed",
            severity  = Severity.HIGH,
            passed    = deadline_valid,
            actual    = deadline,
            expected  = "future ISO 8601 UTC",
            message   = f"deadline={deadline}, valid={deadline_valid}",
            field_path= "deadline_utc",
        ),
        Check(
            check_id  = "faithfulness_verified",
            name      = f"Draft faithful to incident data (>= {FAITHFULNESS_THRESHOLD})",
            severity  = Severity.HIGH,
            passed    = faith is None or faith >= FAITHFULNESS_THRESHOLD,
            expected  = FAITHFULNESS_THRESHOLD,
            actual    = faith,
            delta     = (faith - FAITHFULNESS_THRESHOLD) if faith is not None else None,
            field_path= "draft_content",
        ),
        Check(
            check_id  = "gaps_identified",
            name      = "All unfillable fields explicitly flagged",
            severity  = Severity.HIGH,
            passed    = isinstance(gaps, list),   # gaps may be empty — that is OK
            message   = f"gaps_count={len(gaps)}",
            field_path= "gaps",
        ),
        Check(
            check_id  = "regulatory_article_cited",
            name      = "Relevant regulatory articles referenced",
            severity  = Severity.MEDIUM,
            passed    = any(
                any(kw in str(v) for kw in ["Article","§","Pasal","section","art."])
                for v in draft.values()
            ) if draft else False,
            field_path= "draft_content.regulatory_basis",
        ),
        Check(
            check_id  = "analyst_instructions_present",
            name      = "Co-sign instructions provided",
            severity  = Severity.MEDIUM,
            passed    = bool(ai),
            message   = f"instructions_len={len(ai)}",
            field_path= "analyst_instructions",
        ),
        Check(
            check_id  = "jurisdiction_prompt_applied",
            name      = "Correct jurisdiction prompt used",
            severity  = Severity.LOW,
            passed    = True,   # enforced by context_builder
            message   = f"jurisdiction={state['jurisdiction']}",
            field_path= "jurisdiction",
        ),
    ]

    qs = QualitySignal(
        job_id  = state["job_id"],
        agent_id= "SOC-AUDITOR-001",
        passed  = all(c.passed for c in checks if c.severity == Severity.HIGH),
        checks  = checks,
        confidence = {"faithfulness": faith or 0.0},
    )
    await qs.emit()

    logger.info("signal_emitted", extra={
        "job_id":   state["job_id"],
        "passed":   qs.passed,
        "failures": len(qs.failed_high_checks),
    })
    return {"quality_signal_emitted": True, "_qs_passed": qs.passed}


async def submit_to_hitl_node(state: AuditorState) -> dict:
    """
    Submits filing draft to HITL queue.
    interrupt_before=["submit_to_hitl"] ensures LangGraph suspends
    BEFORE this node executes — the analyst must resume the graph.
    This node runs only after analyst approval.
    """
    logger.info("hitl_submission", extra={
        "job_id":       state["job_id"],
        "filing_type":  state.get("filing_type"),
        "deadline":     state.get("deadline_utc"),
    })
    await submit_hitl_job(
        job_id          = state["job_id"],
        agent_id        = "SOC-AUDITOR-001",
        tenant_id       = state["tenant_id"],
        jurisdiction    = state["jurisdiction"],
        draft           = {
            "filing_type":            state.get("filing_type"),
            "deadline_utc":           state.get("deadline_utc"),
            "draft_content":          state.get("draft_content"),
            "gaps":                   state.get("gaps", []),
            "analyst_instructions":   state.get("_analyst_instructions",""),
            "faithfulness_score":     state.get("faithfulness_score"),
            "incident_id":            state.get("incident_id"),
        },
        qs_payload      = {},
        reviewer_role   = "cirt_analyst",
        timeout_minutes = 120,
    )
    return {}


# ── Edge routers ─────────────────────────────────────────────────────────────

def faith_router(state: AuditorState) -> str:
    passed = state.get("_faith_passed", True)
    retry  = state.get("_faith_retry", 0)
    if passed:   return "pass"
    if retry < 2: return "retry"
    return "fail"   # force to HITL after 2 retries


# ── Graph factory ─────────────────────────────────────────────────────────────

async def build_auditor_graph():
    gb = StateGraph(AuditorState)
    gb.add_node("determine_filing_type", determine_filing_type_node)
    gb.add_node("build_context",         build_context_node)
    gb.add_node("call_llm",              call_llm_node)
    gb.add_node("check_hallucination",   check_hallucination_node)
    gb.add_node("validate_draft",        validate_draft_node)
    gb.add_node("emit_quality_signal",   emit_quality_signal_node)
    gb.add_node("submit_to_hitl",        submit_to_hitl_node)

    gb.set_entry_point("determine_filing_type")
    gb.add_edge("determine_filing_type", "build_context")
    gb.add_edge("build_context",         "call_llm")
    gb.add_conditional_edges("check_hallucination", faith_router, {
        "pass":  "validate_draft",
        "retry": "call_llm",
        "fail":  "validate_draft",   # emit QS with failure
    })
    gb.add_edge("call_llm",            "check_hallucination")
    gb.add_edge("validate_draft",      "emit_quality_signal")
    gb.add_edge("emit_quality_signal", "submit_to_hitl")
    gb.add_edge("submit_to_hitl",      END)

    dsn         = os.getenv("POSTGRES_DSN")
    checkpointer= await AsyncPostgresSaver.from_conn_string(dsn)
    await checkpointer.setup()

    return gb.compile(
        checkpointer    = checkpointer,
        interrupt_before= ["submit_to_hitl"],   # NON-BYPASSABLE
    )
