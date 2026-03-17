"""agents/triage/tools.py — Tool definitions and OPA-enforced dispatcher."""

from __future__ import annotations
import ipaddress, json, os
from langchain_core.tools import tool
from core.opa_client     import check_action
from core.logger         import get_logger

logger = get_logger(__name__)


# ── Tool definitions (shown to LLM via bind_tools) ───────────────────────────

@tool
async def query_event_history(
    tenant_id: str,
    asset_id: str,
    event_type: str = "",
    lookback_hours: int = 24,
) -> str:
    """
    Query historical security events for a specific asset.
    Use to detect repeat offenders, brute-force patterns, and recurrence.
    Max lookback: 168 hours (7 days).
    """
    return json.dumps({"__tool__": "query_event_history",
                       "tenant_id": tenant_id, "asset_id": asset_id,
                       "event_type": event_type or None,
                       "lookback_hours": min(lookback_hours, 168)})


@tool
async def query_asset_profile(tenant_id: str, asset_id: str) -> str:
    """
    Retrieve the security profile of an asset.
    Returns: criticality, internet_facing, firewall_protected, data_sensitivity,
             owner, services, network_segment, ncii_sector_relevance.
    """
    return json.dumps({"__tool__": "query_asset_profile",
                       "tenant_id": tenant_id, "asset_id": asset_id})


@tool
async def query_threat_intel(
    tenant_id: str,
    ioc_value: str,
    ioc_type: str = "ip",
) -> str:
    """
    Look up threat intelligence for an IOC (indicator of compromise).
    ioc_type: ip | domain | hash | url
    Returns: reputation, confidence, associated TTPs, known campaigns.
    """
    return json.dumps({"__tool__": "query_threat_intel",
                       "tenant_id": tenant_id, "ioc_value": ioc_value,
                       "ioc_type": ioc_type})


TRIAGE_TOOLS = [query_event_history, query_asset_profile, query_threat_intel]


# ── OPA-enforced dispatcher ───────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    try: ipaddress.ip_address(s); return True
    except: return False

def _in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
    except: return False


async def dispatch_tool(
    tool_name:        str,
    args:             dict,
    current_tenant_id: str,
    asset_cidr_ranges: list[str],
    siem,               # SIEMAdapter or MockSIEM instance
) -> str:
    """
    Execute a tool call after 3-layer validation.
    Returns JSON string to inject into LangGraph messages.
    Always returns JSON (never raises) so LLM can see denial reason.
    """
    # ── Check 1: OPA policy ──────────────────────────────────────────────────
    allow, risk = await check_action({
        "identity_type":      "service",
        "agent_id":           "SOC-TRIAGE-001",
        "current_tenant_id":  current_tenant_id,
        "requested_tenant_id":args.get("tenant_id", ""),
        "tool_name":          tool_name,
        "resource_id":        args.get("asset_id") or args.get("ioc_value", ""),
    })
    if not allow:
        logger.warning("tool_opa_denied", extra={
            "tool":      tool_name,
            "tenant":    current_tenant_id,
            "requested": args.get("tenant_id"),
        })
        return json.dumps({
            "error":  "access_denied",
            "reason": "OPA policy denied this tool call",
            "tool":   tool_name,
        })

    # ── Check 2: Python tenant_id match ─────────────────────────────────────
    if args.get("tenant_id") != current_tenant_id:
        return json.dumps({
            "error":  "tenant_id_mismatch",
            "reason": f"Tool tenant_id={args.get('tenant_id')!r} != current={current_tenant_id!r}",
        })

    # ── Check 3: CIDR scope (for asset-based tools) ──────────────────────────
    asset_id = args.get("asset_id", "")
    if tool_name in ("query_event_history", "query_asset_profile") and asset_id:
        if _is_ip(asset_id) and not _in_cidrs(asset_id, asset_cidr_ranges):
            return json.dumps({
                "error":  "asset_out_of_scope",
                "reason": f"Asset IP {asset_id!r} not in tenant CIDR ranges",
                "cidrs":  asset_cidr_ranges,
            })

    # ── Execute ──────────────────────────────────────────────────────────────
    try:
        if tool_name == "query_event_history":
            result = await siem.get_event_history(
                tenant_id    = args["tenant_id"],
                asset_id     = args["asset_id"],
                event_type   = args.get("event_type") or None,
                lookback_hours = int(args.get("lookback_hours", 24)),
            )
        elif tool_name == "query_asset_profile":
            result = await siem.get_asset_profile(
                tenant_id = args["tenant_id"],
                asset_id  = args["asset_id"],
            )
        elif tool_name == "query_threat_intel":
            result = await siem.get_threat_intel(
                tenant_id = args["tenant_id"],
                ioc_value = args["ioc_value"],
                ioc_type  = args.get("ioc_type", "ip"),
            )
        else:
            return json.dumps({"error": "unknown_tool", "tool": tool_name})

        logger.info("tool_executed", extra={
            "tool":      tool_name,
            "tenant":    current_tenant_id,
            "risk":      risk,
        })
        return json.dumps(result)

    except Exception as e:
        logger.error("tool_execution_failed", extra={
            "tool": tool_name, "error": str(e)
        })
        return json.dumps({"error": "tool_failed", "detail": str(e)})
