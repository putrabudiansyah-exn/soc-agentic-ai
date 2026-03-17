"""
agents/triage/graph.py — Full LangGraph StateGraph for the Triage Agent.

SHIM SWAP POINTS (at SAO migration — see migration_checklist.md):
  core.quality_signal → sao_sdk.quality
  core.cost_tracker   → sao_sdk.cost
  core.logger         → sao_sdk.logging

Everything else is UNCHANGED at migration.
"""

from __future__ import annotations
import json, operator, os
from typing import Annotated
from typing_extensions import TypedDict

from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.graph          import StateGraph, END
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

# Core modules (unchanged at migration)
from core.context_builder  import build_system_prompt
from core.tenant_registry  import get_tenant
from core.llm_client       import get_llm
from core.opa_client       import check_action
from core.logger           import get_logger  # SAO migration: from sao_sdk.logging import get_logger

# Shims (swapped at migration)
from core.quality_signal   import QualitySignal, Check, Severity  # → sao_sdk.quality
from core.cost_tracker     import write_token_cost_event           # → sao_sdk.cost

# Agent-specific
from agents.triage.tier_classifier import classify_tier
from agents.triage.tools           import TRIAGE_TOOLS, dispatch_tool

logger = get_logger(__name__)

SOFT_CAP_TOKENS = 1_200
HARD_CAP_TOKENS = 2_000
MAX_TOOL_CALLS  = 3


# ── State ─────────────────────────────────────────────────────────────────────
class TriageState(TypedDict):
    # SAO-required fields
    job_id:         str
    department_id:  str
    # Inputs
    tenant_id:      str
    jurisdiction:   str
    event:          dict
    # LangGraph message accumulator
    messages:       Annotated[list, operator.add]
    # Runtime state
    tool_call_count: int
    opa_denials:    int
    budget_status:  str   # OK | TRUNCATE_ENRICHMENT | EXHAUSTED
    _retry_count:   int   # hallucination retries
    assessment:     dict | None
    tier:           int | None
    tier_rationale: str | None
    hitl_required:  bool
    auto_resolved:  bool
    quality_signal_emitted: bool


# ── Nodes ─────────────────────────────────────────────────────────────────────

async def build_context_node(state: TriageState) -> dict:
    tenant        = get_tenant(state["tenant_id"])
    system_prompt = build_system_prompt(tenant, "triage")
    return {"messages": [SystemMessage(content=system_prompt)]}


async def check_budget_node(state: TriageState) -> dict:
    event_tokens = len(json.dumps(state["event"])) // 4
    if event_tokens > HARD_CAP_TOKENS:
        logger.warning("budget_exhausted", extra={
            "job_id": state["job_id"], "tokens": event_tokens
        })
        return {"budget_status": "EXHAUSTED"}
    if event_tokens > SOFT_CAP_TOKENS:
        return {"budget_status": "TRUNCATE_ENRICHMENT"}
    return {"budget_status": "OK"}


async def call_llm_node(state: TriageState) -> dict:
    llm = get_llm(temperature=0.1, max_tokens=1_200)

    # First call: add the event as a HumanMessage
    if not any(isinstance(m, HumanMessage) for m in state["messages"]):
        event_content = (
            "Analyse this security event and return your assessment as strict JSON.\n"
            "Do not include any text before or after the JSON object.\n\n"
            f"Event:\n{json.dumps(state['event'], indent=2)}"
        )
        messages = state["messages"] + [HumanMessage(content=event_content)]
    else:
        messages = state["messages"]

    # Strip tool calls if budget is exhausted — do not enrich
    if state["budget_status"] == "EXHAUSTED":
        llm_no_tools = get_llm(temperature=0.1, max_tokens=800)
        response = await llm_no_tools.ainvoke(messages)
    else:
        llm_with_tools = llm.bind_tools(TRIAGE_TOOLS)
        response = await llm_with_tools.ainvoke(messages)

    # Mandatory cost event after every LLM call
    usage = getattr(response, "usage_metadata", {}) or {}
    write_token_cost_event({    # SAO migration: await sao_sdk.cost.write_token_cost_event(...)
        "job_id":             state["job_id"],
        "tenant_id":          state["tenant_id"],
        "department_id":      state["department_id"],
        "agent_id":           "SOC-TRIAGE-001",
        "model":              "llama-3.3-70b",
        "node_name":          "call_llm",
        "prompt_tokens":      usage.get("input_tokens",  0),
        "completion_tokens":  usage.get("output_tokens", 0),
        "cost_usd":           0.0,
    })

    logger.info("llm_call", extra={
        "job_id":  state["job_id"],
        "tokens":  usage.get("output_tokens", 0),
        "has_tool_calls": bool(getattr(response, "tool_calls", [])),
    })
    return {"messages": [response]}


async def opa_tool_check_node(state: TriageState) -> dict:
    last = state["messages"][-1]
    if not hasattr(last, "tool_calls") or not last.tool_calls:
        return {}

    tenant    = get_tenant(state["tenant_id"])
    tool_call = last.tool_calls[0]
    args      = tool_call.get("args", {})

    # Delegate to the OPA-enforced dispatcher
    result_json = await dispatch_tool(
        tool_name          = tool_call["name"],
        args               = args,
        current_tenant_id  = state["tenant_id"],
        asset_cidr_ranges  = tenant.asset_cidr_ranges,
        siem               = _get_siem(state["tenant_id"]),
    )
    result = json.loads(result_json)

    if "error" in result:
        # Denial — inject error as ToolMessage so LLM sees it
        return {
            "opa_denials": state["opa_denials"] + 1,
            "messages": [ToolMessage(
                content        = result_json,
                tool_call_id   = tool_call.get("id", ""),
                name           = tool_call["name"],
            )],
            "_opa_allowed": False,
        }

    return {
        "tool_call_count": state["tool_call_count"] + 1,
        "_opa_allowed":    True,
        "_tool_result":    result_json,
        "_tool_call_id":   tool_call.get("id", ""),
        "_tool_name":      tool_call["name"],
    }


async def execute_tools_node(state: TriageState) -> dict:
    """Inject already-executed tool result as ToolMessage for LLM context."""
    result_json = state.get("_tool_result", "{}")
    return {"messages": [ToolMessage(
        content      = result_json,
        tool_call_id = state.get("_tool_call_id", ""),
        name         = state.get("_tool_name",    ""),
    )]}


async def check_hallucination_node(state: TriageState) -> dict:
    last = state["messages"][-1]
    if not hasattr(last, "content") or not last.content:
        return {"_hallucination_passed": None}
    try:
        from deepeval.metrics   import FaithfulnessMetric, AnswerRelevancyMetric
        from deepeval.test_case import LLMTestCase
        context = [str(m.content) for m in state["messages"][:-1] if hasattr(m,"content")]
        tc = LLMTestCase(
            input            = json.dumps(state["event"]),
            actual_output    = str(last.content),
            retrieval_context= context,
        )
        f = FaithfulnessMetric(threshold=0.85)
        r = AnswerRelevancyMetric(threshold=0.80)
        f.measure(tc); r.measure(tc)
        passed = f.is_successful() and r.is_successful()
        return {"_hallucination_passed": passed}
    except Exception as e:
        logger.warning("deepeval_unavailable", extra={"error": str(e)})
        return {"_hallucination_passed": None}  # unknown — continue


async def classify_tier_node(state: TriageState) -> dict:
    last       = state["messages"][-1]
    assessment = {}
    if hasattr(last, "content") and last.content:
        try:
            content = str(last.content).strip()
            # Strip markdown fences if model ignored the instruction
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            assessment = json.loads(content.strip())
        except json.JSONDecodeError:
            logger.warning("llm_json_parse_failed", extra={"job_id": state["job_id"]})

    # Force-escalate paths: budget exhausted, tool cap hit, OPA denials
    if (state["budget_status"] == "EXHAUSTED"
            or state["tool_call_count"] >= MAX_TOOL_CALLS
            or state["opa_denials"] > 0):
        assessment.setdefault("confidence",                 0.0)
        assessment.setdefault("severity_assessment",        "unknown")
        assessment.setdefault("lateral_movement_indicators",False)
        assessment.setdefault("asset_criticality",          "standard")
        assessment.setdefault("novelty_score",              0.5)

    tier, rationale = classify_tier(assessment)

    logger.info("tier_classified", extra={
        "job_id":    state["job_id"],
        "tier":      tier,
        "rationale": rationale,
        "confidence":assessment.get("confidence", 0),
    })
    return {"assessment": assessment, "tier": tier, "tier_rationale": rationale}


async def emit_quality_signal_node(state: TriageState) -> dict:
    a = state.get("assessment") or {}

    checks = [
        Check(
            check_id  = "event_context_complete",
            name      = "Event context assembled without error",
            severity  = Severity.HIGH,
            passed    = len(state["messages"]) >= 2 and bool(state.get("event")),
            message   = f"messages={len(state['messages'])}, event_present={bool(state.get('event'))}",
            field_path= "event",
        ),
        Check(
            check_id  = "tier_determination_valid",
            name      = "Tier classification produced valid output",
            severity  = Severity.HIGH,
            passed    = state.get("tier") in (1, 2, 3) and bool(state.get("tier_rationale")),
            expected  = "1|2|3",
            actual    = state.get("tier"),
            delta     = None,
            message   = f"tier={state.get('tier')}, rationale_present={bool(state.get('tier_rationale'))}",
            field_path= "tier",
        ),
        Check(
            check_id  = "confidence_adequate",
            name      = "Model confidence meets threshold (>= 0.6)",
            severity  = Severity.HIGH,
            passed    = float(a.get("confidence", 0)) >= 0.6,
            expected  = 0.6,
            actual    = float(a.get("confidence", 0)),
            delta     = float(a.get("confidence", 0)) - 0.6,
            field_path= "assessment.confidence",
        ),
        Check(
            check_id  = "lateral_movement_assessed",
            name      = "Lateral movement field evaluated",
            severity  = Severity.HIGH,
            passed    = ("lateral_movement_indicators" in a
                         and isinstance(a["lateral_movement_indicators"], bool)),
            message   = f"field_present={'lateral_movement_indicators' in a}",
            field_path= "assessment.lateral_movement_indicators",
        ),
        Check(
            check_id  = "tenant_isolation_verified",
            name      = "All tool calls within tenant scope",
            severity  = Severity.HIGH,
            passed    = state["opa_denials"] == 0,
            expected  = 0,
            actual    = state["opa_denials"],
            delta     = float(-state["opa_denials"]),
            message   = f"opa_denials={state['opa_denials']}",
            field_path= "tool_calls",
        ),
        Check(
            check_id  = "tool_cap_respected",
            name      = "Tool call count within limit (<= 3)",
            severity  = Severity.MEDIUM,
            passed    = state["tool_call_count"] <= MAX_TOOL_CALLS,
            expected  = MAX_TOOL_CALLS,
            actual    = state["tool_call_count"],
            delta     = float(state["tool_call_count"] - MAX_TOOL_CALLS),
            field_path= "tool_call_count",
        ),
        Check(
            check_id  = "token_budget_respected",
            name      = "Event within token budget",
            severity  = Severity.LOW,
            passed    = state["budget_status"] != "EXHAUSTED",
            message   = state["budget_status"],
            field_path= "budget",
        ),
    ]

    qs = QualitySignal(
        job_id     = state["job_id"],
        agent_id   = "SOC-TRIAGE-001",
        passed     = all(c.passed for c in checks if c.severity == Severity.HIGH),
        checks     = checks,
        confidence = {"confidence": float(a.get("confidence", 0))},
    )
    await qs.emit()

    logger.info("signal_emitted", extra={
        "job_id":   state["job_id"],
        "passed":   qs.passed,
        "failures": len(qs.failed_high_checks),
    })
    return {
        "quality_signal_emitted": True,
        "hitl_required":          not qs.passed or state.get("tier", 1) >= 2,
    }


async def route_result_node(state: TriageState) -> dict:
    tier = state.get("tier", 2)
    if state["hitl_required"] or tier >= 2:
        logger.info("hitl_triggered", extra={
            "job_id":        state["job_id"],
            "tier":          tier,
            "hitl_required": state["hitl_required"],
        })
        return {"hitl_required": True}
    else:
        logger.info("auto_resolved", extra={
            "job_id": state["job_id"], "tier": tier
        })
        return {"auto_resolved": True}


# ── Edge routers ──────────────────────────────────────────────────────────────

def budget_router(state: TriageState) -> str:
    return "exhausted" if state["budget_status"] == "EXHAUSTED" else "ok"


def llm_router(state: TriageState) -> str:
    last = state["messages"][-1]
    if state["tool_call_count"] >= MAX_TOOL_CALLS:
        return "cap"
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "tool_call"
    return "response"


def opa_router(state: TriageState) -> str:
    if not state.get("_opa_allowed", True):
        return "deny"
    return "allow"


def hallucination_router(state: TriageState) -> str:
    result = state.get("_hallucination_passed")
    if result is None:
        return "pass"   # DeepEval unavailable — continue
    if result:
        return "pass"
    retry = state.get("_retry_count", 0) + 1
    if retry >= 2:
        return "fail"
    return "retry"


# ── SIEM factory ─────────────────────────────────────────────────────────────

def _get_siem(tenant_id: str):
    """Return MockSIEM in dev, WazuhAdapter in prod."""
    wazuh_url = os.getenv("WAZUH_BASE_URL", "mock")
    if wazuh_url == "mock":
        from core.siem_mock import MockSIEM
        return MockSIEM(tenant_id)
    from core.siem_adapter import WazuhAdapter
    return WazuhAdapter()


# ── Graph factory ─────────────────────────────────────────────────────────────

async def build_triage_graph():
    gb = StateGraph(TriageState)

    gb.add_node("build_context",       build_context_node)
    gb.add_node("check_budget",        check_budget_node)
    gb.add_node("call_llm",            call_llm_node)
    gb.add_node("opa_tool_check",      opa_tool_check_node)
    gb.add_node("execute_tools",       execute_tools_node)
    gb.add_node("check_hallucination", check_hallucination_node)
    gb.add_node("classify_tier",       classify_tier_node)
    gb.add_node("emit_quality_signal", emit_quality_signal_node)
    gb.add_node("route_result",        route_result_node)

    gb.set_entry_point("build_context")
    gb.add_edge("build_context", "check_budget")

    gb.add_conditional_edges("check_budget", budget_router, {
        "ok":       "call_llm",
        "exhausted":"classify_tier",
    })

    gb.add_conditional_edges("call_llm", llm_router, {
        "tool_call":"opa_tool_check",
        "response": "check_hallucination",
        "cap":      "classify_tier",
    })

    gb.add_conditional_edges("opa_tool_check", opa_router, {
        "allow": "execute_tools",
        "deny":  "call_llm",
    })

    gb.add_edge("execute_tools",       "call_llm")

    gb.add_conditional_edges("check_hallucination", hallucination_router, {
        "pass":  "classify_tier",
        "retry": "call_llm",
        "fail":  "classify_tier",   # force-classify after max retries
    })

    gb.add_edge("classify_tier",       "emit_quality_signal")
    gb.add_edge("emit_quality_signal", "route_result")
    gb.add_edge("route_result",        END)

    dsn         = os.getenv("POSTGRES_DSN")
    checkpointer= await AsyncPostgresSaver.from_conn_string(dsn)
    await checkpointer.setup()

    return gb.compile(
        checkpointer   = checkpointer,
        interrupt_before= ["route_result"],
    )
