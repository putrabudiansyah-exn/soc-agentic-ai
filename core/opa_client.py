"""core/opa_client.py — OPA policy enforcement. Fail closed. Unchanged at SAO migration."""
from __future__ import annotations
import os
import httpx
from core.logger import get_logger

logger = get_logger(__name__)

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/sao/agent/policy")


async def check_action(input_payload: dict) -> tuple[bool, str]:
    """
    POST to OPA. Returns (allow: bool, risk_level: str).
    FAIL CLOSED on any error — never return True on failure.
    Unchanged at SAO migration (same OPA address, same policy).
    """
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            resp = await c.post(OPA_URL, json={"input": input_payload})
            resp.raise_for_status()
            result = resp.json().get("result", {})
            allow      = bool(result.get("allow", False))
            risk_level = str(result.get("risk_level", "unknown"))

            if not allow:
                deny_reasons = result.get("deny", [])
                logger.warning("opa_denied",
                    extra={
                        "agent_id":   input_payload.get("agent_id"),
                        "tool":       input_payload.get("tool_name"),
                        "tenant":     input_payload.get("current_tenant_id"),
                        "reasons":    deny_reasons,
                    })
            return allow, risk_level

    except httpx.TimeoutException:
        logger.error("opa_timeout — failing closed",
                     extra={"url": OPA_URL})
        return False, "opa_timeout"
    except Exception as e:
        logger.error("opa_error — failing closed",
                     extra={"error": str(e), "url": OPA_URL})
        return False, "opa_error"
