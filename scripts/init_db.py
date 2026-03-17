#!/usr/bin/env python3
"""
scripts/init_db.py — Create all tables for the lightweight stack.
Run once after docker compose up -d.
Usage: python scripts/init_db.py
"""

import asyncio, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncpg
import clickhouse_connect
from dotenv import load_dotenv
load_dotenv()


POSTGRES_SCHEMA = """
-- Quality Signal storage (equivalent to SAO quality_signals table)
CREATE TABLE IF NOT EXISTS quality_signals (
    job_id      TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    checked_at  TEXT NOT NULL,
    passed      BOOLEAN NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_qs_agent_id  ON quality_signals(agent_id);
CREATE INDEX IF NOT EXISTS idx_qs_passed    ON quality_signals(passed);
CREATE INDEX IF NOT EXISTS idx_qs_created   ON quality_signals(created_at);

-- LangGraph checkpoints (PostgresSaver creates its own tables but
-- we also store a simplified job registry for the HITL UI)
CREATE TABLE IF NOT EXISTS jobs (
    job_id        TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    jurisdiction  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    -- PENDING | PROCESSING | HITL_PENDING | COMPLETE | FAILED
    input         JSONB,
    output        JSONB,
    hitl_decision TEXT,   -- APPROVE | REJECT | ESCALATE | null
    reviewer_id   TEXT,
    reviewer_notes TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_jobs_status     ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_tenant     ON jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created    ON jobs(created_at);

-- HITL queue (jobs awaiting analyst review)
CREATE TABLE IF NOT EXISTS hitl_queue (
    job_id          TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    jurisdiction    TEXT NOT NULL,
    reviewer_role   TEXT NOT NULL DEFAULT 'analyst',
    draft           JSONB NOT NULL,
    quality_signal  JSONB NOT NULL,
    timeout_at      TIMESTAMPTZ,
    submitted_at    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    decision        TEXT,    -- APPROVE | REJECT | ESCALATE | TIMEOUT
    reviewer_id     TEXT,
    reviewer_notes  TEXT,
    content_hash    TEXT     -- SHA-256 of draft at time of approval
);
CREATE INDEX IF NOT EXISTS idx_hitl_status  ON hitl_queue(decision) WHERE decision IS NULL;
CREATE INDEX IF NOT EXISTS idx_hitl_tenant  ON hitl_queue(tenant_id);

-- Asset registry (populated by nmap onboarding pipeline)
CREATE TABLE IF NOT EXISTS asset_registry (
    tenant_id   TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    profile     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (tenant_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_tenant ON asset_registry(tenant_id);

-- Audit log (immutable — append only)
CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGSERIAL PRIMARY KEY,
    job_id        TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    event_data    JSONB NOT NULL,
    recorded_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_job    ON audit_log(job_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
"""

CLICKHOUSE_SCHEMA = """
CREATE DATABASE IF NOT EXISTS soc_metrics;

CREATE TABLE IF NOT EXISTS soc_metrics.token_events (
    job_id          String,
    tenant_id       String,
    department_id   String,
    agent_id        String,
    model           String,
    node_name       String,
    prompt_tokens   UInt32,
    completion_tokens UInt32,
    cost_usd        Float32,
    recorded_at     DateTime
) ENGINE = MergeTree()
ORDER BY (tenant_id, agent_id, recorded_at)
PARTITION BY toYYYYMM(recorded_at);
"""

# ── Seed data for dev/eval ────────────────────────────────────────────────────
SEED_ASSETS = [
    ("eval-tenant-id", "srv-auth-01", {
        "asset_id": "srv-auth-01", "hostname": "srv-auth-01", "ip": "10.99.4.22",
        "criticality": "critical", "data_sensitivity": "high",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "identity-team",
        "services": ["LDAP", "Kerberos"], "ncii_sector_relevance": True,
    }),
    ("eval-tenant-id", "srv-db-01", {
        "asset_id": "srv-db-01", "hostname": "srv-db-01", "ip": "10.99.3.11",
        "criticality": "critical", "data_sensitivity": "restricted",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "dba-team",
    }),
    ("eval-tenant-id", "srv-web-01", {
        "asset_id": "srv-web-01", "hostname": "srv-web-01", "ip": "10.99.1.22",
        "criticality": "important", "data_sensitivity": "medium",
        "internet_facing": True, "firewall_protected": False,
        "network_segment": "DMZ", "owner": "web-team",
    }),
    ("eval-tenant-id", "ws-finance-07", {
        "asset_id": "ws-finance-07", "hostname": "ws-finance-07", "ip": "10.99.2.55",
        "criticality": "important", "data_sensitivity": "high",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "finance-team",
    }),
    ("eval-tenant-id", "ws-dev-03", {
        "asset_id": "ws-dev-03", "hostname": "ws-dev-03", "ip": "10.99.6.33",
        "criticality": "standard", "data_sensitivity": "low",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "dev-team",
    }),
]

import json as _json

async def init_postgres():
    dsn  = os.getenv("POSTGRES_DSN", "postgresql://soc:soc@localhost:5432/socdev")
    conn = await asyncpg.connect(dsn)
    print("PostgreSQL: creating schema...")
    await conn.execute(POSTGRES_SCHEMA)
    print("PostgreSQL: seeding eval assets...")
    for (tid, aid, profile) in SEED_ASSETS:
        await conn.execute(
            """
            INSERT INTO asset_registry (tenant_id, asset_id, profile)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, asset_id) DO NOTHING
            """,
            tid, aid, _json.dumps(profile),
        )
    await conn.close()
    print("PostgreSQL: done.")

def init_clickhouse():
    url = os.getenv("CLICKHOUSE_URL", "http://localhost:8123")
    host, port = url.replace("http://","").split(":")
    client = clickhouse_connect.get_client(host=host, port=int(port))
    print("ClickHouse: creating schema...")
    for stmt in CLICKHOUSE_SCHEMA.strip().split(";\n"):
        stmt = stmt.strip()
        if stmt:
            client.command(stmt)
    print("ClickHouse: done.")

async def main():
    print("Initialising lightweight stack databases...\n")
    await init_postgres()
    init_clickhouse()
    print("\nAll done. Run: python scripts/run_event.py --help")

if __name__ == "__main__":
    asyncio.run(main())
