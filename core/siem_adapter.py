"""core/siem_adapter.py — SIEM abstraction. Unchanged at migration."""
from __future__ import annotations
from abc import ABC, abstractmethod
import os
import httpx
from core.asset_registry import get_asset


class SIEMAdapter(ABC):
    @abstractmethod
    async def get_event_history(
        self, tenant_id: str, asset_id: str,
        event_type: str | None, lookback_hours: int,
    ) -> dict: ...

    @abstractmethod
    async def get_asset_profile(self, tenant_id: str, asset_id: str) -> dict: ...

    @abstractmethod
    async def get_threat_intel(
        self, tenant_id: str, ioc_value: str, ioc_type: str,
    ) -> dict: ...


class WazuhAdapter(SIEMAdapter):
    """Queries Wazuh REST API v4."""

    def __init__(self):
        self.base_url = os.getenv("WAZUH_BASE_URL", "https://wazuh-manager:55000")
        self.api_user = os.getenv("WAZUH_API_USER", "wazuh-api")
        self.api_pass = os.getenv("WAZUH_API_PASS", "")
        self._token: str | None = None

    async def _get_token(self) -> str:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
            r = await c.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.api_user, self.api_pass),
            )
            r.raise_for_status()
            return r.json()["data"]["token"]

    async def _headers(self) -> dict:
        if not self._token:
            self._token = await self._get_token()
        return {"Authorization": f"Bearer {self._token}"}

    async def get_event_history(
        self, tenant_id: str, asset_id: str,
        event_type: str | None = None, lookback_hours: int = 24,
    ) -> dict:
        q = f"rule.level>=7;agent.name={asset_id}"
        if event_type:
            q += f";rule.groups~{event_type}"
        async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
            r = await c.get(
                f"{self.base_url}/alerts",
                params={"q": q, "limit": 100, "pretty": "true"},
                headers=await self._headers(),
            )
            r.raise_for_status()
            items = r.json()["data"]["affected_items"]
        return {"asset_id": asset_id, "events": items, "count": len(items)}

    async def get_asset_profile(self, tenant_id: str, asset_id: str) -> dict:
        # Try asset registry first (populated by nmap onboarding)
        profile = await get_asset(tenant_id, asset_id)
        if profile:
            return profile
        # Fall back to Wazuh agent info
        async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
            r = await c.get(
                f"{self.base_url}/agents",
                params={"search": asset_id, "limit": 1},
                headers=await self._headers(),
            )
            items = r.json()["data"]["affected_items"]
            agent = items[0] if items else {}
        return {
            "asset_id":           asset_id,
            "hostname":           agent.get("name", asset_id),
            "ip":                 agent.get("ip", "unknown"),
            "os":                 agent.get("os", {}).get("full", "unknown"),
            "criticality":        "standard",
            "data_sensitivity":   "low",
            "internet_facing":    False,
            "firewall_protected": True,
            "source":             "wazuh_fallback",
        }

    async def get_threat_intel(
        self, tenant_id: str, ioc_value: str, ioc_type: str,
    ) -> dict:
        # Wazuh threat intel integration (VirusTotal, OTX, MISP)
        # Stub — connect to your configured Wazuh integrations
        return {"reputation": "unknown", "confidence": 0.0, "ttps": [], "campaigns": []}
