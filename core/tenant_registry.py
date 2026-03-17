"""core/tenant_registry.py — Tenant configuration store."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class TenantConfig:
    tenant_id:          str
    tenant_name:        str
    jurisdiction:       str          # MY | ID | DE
    ncii_sector:        str | None   # BFSI | Telco | Energy | Water | Gov | None
    asset_cidr_ranges:  list[str]
    department_id:      str
    wazuh_agent_group:  str
    daily_token_budget: int = 578_000


# ── Registry ──────────────────────────────────────────────────────────────────
# Dev: in-memory dict. Prod: replace get_tenant() with PostgreSQL query.
TENANTS: dict[str, TenantConfig] = {

    # Indonesia pilot client
    "tenant-pilot-id": TenantConfig(
        tenant_id         = "tenant-pilot-id",
        tenant_name       = "PT Pilot Indonesia",
        jurisdiction      = "ID",
        ncii_sector       = "BFSI",
        asset_cidr_ranges = ["10.10.0.0/16", "172.20.0.0/20"],
        department_id     = "soc-id-bfsi",
        wazuh_agent_group = "pilot-id",
    ),

    # Malaysia pilot client (for parallel prompt dev)
    "tenant-pilot-my": TenantConfig(
        tenant_id         = "tenant-pilot-my",
        tenant_name       = "Acme Bank Malaysia",
        jurisdiction      = "MY",
        ncii_sector       = "BFSI",
        asset_cidr_ranges = ["10.20.0.0/16", "172.30.0.0/20"],
        department_id     = "soc-my-bfsi",
        wazuh_agent_group = "pilot-my",
    ),

    # Eval tenants (used by eval pipeline only)
    "eval-tenant-id": TenantConfig(
        tenant_id         = "eval-tenant-id",
        tenant_name       = "Eval Tenant Indonesia",
        jurisdiction      = "ID",
        ncii_sector       = None,
        asset_cidr_ranges = ["10.99.0.0/16"],
        department_id     = "soc-eval",
        wazuh_agent_group = "eval-id",
    ),
    "eval-tenant-my": TenantConfig(
        tenant_id         = "eval-tenant-my",
        tenant_name       = "Eval Tenant Malaysia",
        jurisdiction      = "MY",
        ncii_sector       = None,
        asset_cidr_ranges = ["10.98.0.0/16"],
        department_id     = "soc-eval",
        wazuh_agent_group = "eval-my",
    ),
}


def get_tenant(tenant_id: str) -> TenantConfig:
    if tenant_id not in TENANTS:
        raise ValueError(f"Unknown tenant: {tenant_id!r}. Add to TENANTS in tenant_registry.py")
    return TENANTS[tenant_id]


def get_jurisdiction(tenant_id: str) -> str:
    return get_tenant(tenant_id).jurisdiction


def list_tenants() -> list[str]:
    return list(TENANTS.keys())
