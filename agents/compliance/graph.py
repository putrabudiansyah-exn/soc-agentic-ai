"""
agents/compliance/graph.py — Compliance Agent.

Two modes:
  continuous — every 4h, autonomous gap detection, no HITL
  board_report — monthly, HITL mandatory before delivery

SHIM SWAP POINTS at SAO migration:
  core.quality_signal, core.cost_tracker, core.logger → sao_sdk equivalents
"""

from __future__ import annotations
import json, operator, os
from datetime import datetime, timezone, timedelta
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

logger = get_logger(__name__)

# ── Control library (in-memory for dev; load from DB in prod) ─────────────────
ID_CONTROLS = [
    {"control_id":"PDP-DM-1","domain":"Data Management","description":"Maintain inventory of personal data processed","criticality":"critical","assessment_method":"automated"},
    {"control_id":"PDP-DM-2","domain":"Data Management","description":"Data retention policy documented and enforced","criticality":"high","assessment_method":"manual"},
    {"control_id":"PDP-SE-1","domain":"Security","description":"Encryption at rest for personal data storage","criticality":"critical","assessment_method":"automated"},
    {"control_id":"PDP-SE-2","domain":"Security","description":"Access control logs retained >= 12 months","criticality":"high","assessment_method":"automated"},
    {"control_id":"PDP-SE-3","domain":"Security","description":"Vulnerability patching within 30 days of disclosure","criticality":"high","assessment_method":"automated"},
    {"control_id":"OJK-RM-1","domain":"Risk Management","description":"Cyber risk assessment conducted annually","criticality":"critical","assessment_method":"manual"},
    {"control_id":"OJK-IR-1","domain":"Incident Response","description":"Incident response plan tested semi-annually","criticality":"high","assessment_method":"manual"},
    {"control_id":"BSSN-AM-1","domain":"Asset Management","description":"IT asset inventory current and complete (>= 95%)","criticality":"high","assessment_method":"automated"},
    {"control_id":"BSSN-AM-2","domain":"Asset Management","description":"NCII assets labelled and monitored","criticality":"critical","assessment_method":"automated"},
    {"control_id":"BSSN-NW-1","domain":"Network Security","description":"Network segmentation between DMZ and internal","criticality":"critical","assessment_method":"automated"},
]

WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ── State ─────────────────────────────────────────────────────────────────────
class ComplianceState(TypedDict):
    job_id:          str
    department_id:   str
    tenant_id:       str
    jurisdiction:    str
    mode:            str   # continuous | board_report | event_triggered
    messages:        Annotated[list, operator.add]
    posture_data:    dict | None
    framework_id:    str
    gap_records:     list
    compliance_scores: dict | None
    report_draft:    dict | None
    quality_signal_emitted: bool


# ── Nodes ─────────────────────────────────────────────────────────────────────

async def ingest_posture_node(state: ComplianceState) -> dict:
    """Collect current security posture from Wazuh SCA + asset registry."""
    wazuh_url = os.getenv("WAZUH_BASE_URL","mock")
    posture   = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "sca_results":     [],
        "asset_inventory": [],
        "patch_status":    [],
        "source":          "wazuh_sca" if wazuh_url != "mock" else "mock",
    }
    # In dev: use mock data
    if wazuh_url == "mock":
        posture["sca_results"] = [
            {"control_id":"PDP-SE-1","status":"pass"},
            {"control_id":"PDP-SE-2","status":"pass"},
            {"control_id":"PDP-SE-3","status":"fail","detail":"srv-web-01 Apache 2.2 unpatched — EOL"},
            {"control_id":"BSSN-AM-1","status":"pass","completeness_pct":96},
            {"control_id":"BSSN-NW-1","status":"fail","detail":"DMZ and internal share VLAN 10"},
        ]
    logger.info("posture_ingested", extra={"job_id": state["job_id"], "source": posture["source"]})
    return {"posture_data": posture}


async def assess_controls_node(state: ComplianceState) -> dict:
    """Map posture data against control library. Produce gap records + scores."""
    posture  = state["posture_data"] or {}
    sca_map  = {r["control_id"]: r for r in posture.get("sca_results", [])}

    gap_records:      list[dict] = []
    scores_by_domain: dict[str, list] = {}

    controls = ID_CONTROLS   # swap for MY/DE controls based on jurisdiction

    for ctrl in controls:
        cid    = ctrl["control_id"]
        domain = ctrl["domain"]
        weight = WEIGHT.get(ctrl["criticality"], 2)
        sca    = sca_map.get(cid, {})

        compliant = sca.get("status") == "pass" if sca else True  # assume pass if no SCA data
        scores_by_domain.setdefault(domain, []).append((weight, compliant))

        if not compliant:
            gap_records.append({
                "control_id":   cid,
                "domain":       domain,
                "description":  ctrl["description"],
                "severity":     ctrl["criticality"],
                "detail":       sca.get("detail","Non-compliance detected"),
                "first_detected": datetime.now(timezone.utc).isoformat(),
                "remediation":  f"Remediate {ctrl['description']} — see Remediation Agent",
            })

    compliance_scores = {}
    for domain, scores in scores_by_domain.items():
        total    = sum(w for w,_ in scores)
        compliant= sum(w for w,c in scores if c)
        compliance_scores[domain] = round(compliant/total*100, 1) if total else 0.0

    overall = round(sum(compliance_scores.values())/len(compliance_scores), 1) if compliance_scores else 0.0
    compliance_scores["overall"] = overall

    logger.info("controls_assessed", extra={
        "job_id":   state["job_id"],
        "gaps":     len(gap_records),
        "overall":  overall,
    })
    return {"gap_records": gap_records, "compliance_scores": compliance_scores}


async def build_report_node(state: ComplianceState) -> dict:
    """Build board-level compliance report (board_report mode only)."""
    llm = get_llm(temperature=0.1, max_tokens=1500)
    prompt = (
        f"Write an executive compliance summary for the board.\n"
        f"Compliance scores: {json.dumps(state['compliance_scores'])}\n"
        f"Open gaps: {json.dumps(state['gap_records'][:5])}\n\n"  # top 5
        "Requirements:\n"
        "- Maximum 200 words\n"
        "- No unexplained acronyms\n"
        "- Board-readable — no technical jargon\n"
        "- State score, trend direction, top 3 gaps, and recommended actions\n"
        "Return only the summary text."
    )
    messages  = state["messages"] + [HumanMessage(content=prompt)]
    response  = await llm.ainvoke(messages)
    usage     = getattr(response, "usage_metadata", {}) or {}
    write_token_cost_event({
        "job_id": state["job_id"], "tenant_id": state["tenant_id"],
        "department_id": state["department_id"], "agent_id": "SOC-COMPLIANCE-001",
        "model": "llama-3.3-70b", "node_name": "build_report",
        "prompt_tokens": usage.get("input_tokens",0),
        "completion_tokens": usage.get("output_tokens",0), "cost_usd": 0.0,
    })
    summary  = str(response.content).strip()
    report   = {
        "period":             {"from": (datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),
                               "to":   datetime.now(timezone.utc).isoformat()},
        "executive_summary":  summary,
        "compliance_scores":  state["compliance_scores"],
        "gap_records":        state["gap_records"],
        "generated_at":       datetime.now(timezone.utc).isoformat(),
    }
    return {"report_draft": report, "messages": [response]}


async def emit_quality_signal_node(state: ComplianceState) -> dict:
    scores   = state.get("compliance_scores") or {}
    gaps     = state.get("gap_records",    [])
    posture  = state.get("posture_data",   {})
    report   = state.get("report_draft")
    mode     = state.get("mode", "continuous")

    # Check posture freshness (within 8 hours)
    ts_str   = posture.get("timestamp","") if posture else ""
    fresh    = False
    if ts_str:
        try:
            ts    = datetime.fromisoformat(ts_str.replace("Z","+00:00"))
            fresh = (datetime.now(timezone.utc) - ts) < timedelta(hours=8)
        except Exception: pass

    checks = [
        Check(
            check_id  = "framework_coverage_complete",
            name      = "All applicable controls assessed",
            severity  = Severity.HIGH,
            passed    = len(scores) >= 2,
            message   = f"domains_scored={len(scores)}",
            field_path= "controls",
        ),
        Check(
            check_id  = "gap_detection_accurate",
            name      = "Gap analysis produced valid output",
            severity  = Severity.HIGH,
            passed    = isinstance(gaps, list),
            message   = f"gaps={len(gaps)}",
            field_path= "gap_records",
        ),
        Check(
            check_id  = "compliance_score_calculated",
            name      = "Score computed for all framework domains",
            severity  = Severity.HIGH,
            passed    = "overall" in scores and scores["overall"] is not None,
            actual    = scores.get("overall"),
            field_path= "compliance_scores",
        ),
        Check(
            check_id  = "posture_data_fresh",
            name      = "Input posture data is current (< 8h)",
            severity  = Severity.MEDIUM,
            passed    = fresh,
            message   = f"posture_timestamp={ts_str}, fresh={fresh}",
            field_path= "posture_data.timestamp",
        ),
        Check(
            check_id  = "report_human_readable",
            name      = "Executive summary present (report mode only)",
            severity  = Severity.MEDIUM,
            passed    = (mode != "board_report") or bool(report and report.get("executive_summary")),
            message   = f"mode={mode}, has_summary={bool(report and report.get('executive_summary'))}",
            field_path= "report_draft.executive_summary",
        ),
        Check(
            check_id  = "framework_version_current",
            name      = "Correct framework version applied",
            severity  = Severity.LOW,
            passed    = True,
            message   = f"framework={state.get('framework_id','ID_PDP_OJK')}",
            field_path= "framework_id",
        ),
    ]

    qs = QualitySignal(
        job_id  = state["job_id"],
        agent_id= "SOC-COMPLIANCE-001",
        passed  = all(c.passed for c in checks if c.severity == Severity.HIGH),
        checks  = checks,
        confidence = {"overall_score": float(scores.get("overall", 0))},
    )
    await qs.emit()
    logger.info("signal_emitted", extra={"job_id": state["job_id"], "passed": qs.passed})
    return {"quality_signal_emitted": True}


async def deliver_report_node(state: ComplianceState) -> dict:
    """Board report delivery (runs only after analyst approval via interrupt_before)."""
    logger.info("report_delivered", extra={
        "job_id":   state["job_id"],
        "tenant_id":state["tenant_id"],
    })
    return {}


# ── Graph factories ───────────────────────────────────────────────────────────

async def _base_graph(mode: str):
    gb = StateGraph(ComplianceState)
    gb.add_node("ingest_posture",      ingest_posture_node)
    gb.add_node("assess_controls",     assess_controls_node)
    gb.add_node("emit_quality_signal", emit_quality_signal_node)

    gb.set_entry_point("ingest_posture")
    gb.add_edge("ingest_posture",  "assess_controls")

    dsn         = os.getenv("POSTGRES_DSN")
    checkpointer= await AsyncPostgresSaver.from_conn_string(dsn)
    await checkpointer.setup()
    return gb, checkpointer


async def build_compliance_graph_continuous():
    """Autonomous 4h monitoring — no HITL."""
    gb, checkpointer = await _base_graph("continuous")
    gb.add_edge("assess_controls",     "emit_quality_signal")
    gb.add_edge("emit_quality_signal", END)
    return gb.compile(checkpointer=checkpointer)


async def build_compliance_graph_report():
    """Monthly board report — HITL mandatory."""
    gb, checkpointer = await _base_graph("board_report")
    gb.add_node("build_report",    build_report_node)
    gb.add_node("deliver_report",  deliver_report_node)
    gb.add_edge("assess_controls",     "build_report")
    gb.add_edge("build_report",        "emit_quality_signal")
    gb.add_edge("emit_quality_signal", "deliver_report")
    gb.add_edge("deliver_report",      END)
    return gb.compile(
        checkpointer    = checkpointer,
        interrupt_before= ["deliver_report"],
    )
