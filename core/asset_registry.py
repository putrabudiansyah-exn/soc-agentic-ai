"""core/asset_registry.py — PostgreSQL-backed asset store. Unchanged at migration."""
from __future__ import annotations
import json, os
import asyncpg


async def _pool():
    dsn = os.getenv("POSTGRES_DSN")
    return await asyncpg.create_pool(dsn, min_size=1, max_size=5)

_POOL = None

async def _get_pool():
    global _POOL
    if not _POOL:
        _POOL = await _pool()
    return _POOL


async def get_asset(tenant_id: str, asset_id: str) -> dict | None:
    pool = await _get_pool()
    row  = await pool.fetchrow(
        "SELECT profile FROM asset_registry WHERE tenant_id=$1 AND asset_id=$2",
        tenant_id, asset_id,
    )
    return json.loads(row["profile"]) if row else None


async def upsert_asset(tenant_id: str, asset_id: str, profile: dict) -> None:
    pool = await _get_pool()
    await pool.execute(
        """
        INSERT INTO asset_registry (tenant_id, asset_id, profile, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (tenant_id, asset_id)
        DO UPDATE SET profile = $3, updated_at = NOW()
        """,
        tenant_id, asset_id, json.dumps(profile),
    )


async def list_tenant_assets(tenant_id: str) -> list[dict]:
    pool = await _get_pool()
    rows = await pool.fetch(
        "SELECT asset_id, profile FROM asset_registry WHERE tenant_id=$1",
        tenant_id,
    )
    return [{"asset_id": r["asset_id"], **json.loads(r["profile"])} for r in rows]
