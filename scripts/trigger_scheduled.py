#!/usr/bin/env python3
"""
scripts/trigger_scheduled.py — Manually trigger scheduled agents for local testing.
Simulates what the Kubernetes CronJobs do in production.

Usage:
  # Trigger compliance monitoring for all eval tenants:
  python scripts/trigger_scheduled.py --agent compliance --mode continuous

  # Trigger weekly threat hunt for a specific tenant:
  python scripts/trigger_scheduled.py --agent threat_hunter --mode weekly_scan --tenant eval-tenant-id

  # Trigger monthly board report:
  python scripts/trigger_scheduled.py --agent compliance --mode board_report
"""

import argparse, asyncio, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from dotenv import load_dotenv
load_dotenv()

AGENT_URLS = {
    "triage":       "http://localhost:8080",
    "auditor":      "http://localhost:8081",
    "compliance":   "http://localhost:8082",
    "remediation":  "http://localhost:8083",
    "threat_hunter":"http://localhost:8084",
}

DEFAULT_TENANTS = ["eval-tenant-id", "eval-tenant-my"]


async def trigger(agent: str, mode: str, tenant_id: str) -> dict:
    url     = AGENT_URLS[agent]
    payload = {"tenant_id": tenant_id, "mode": mode}

    # Agent-specific payload additions
    if agent == "compliance":
        payload["framework_id"] = "ID_PDP_OJK" if "id" in tenant_id else "CSA2024_PDPA_BNM"
    if agent == "remediation":
        payload["tier"]             = 2
        payload["incident_context"] = {
            "event_type": "multiple_failed_logins",
            "source_ip":  "203.0.113.42",
            "destination_asset": "srv-auth-01",
        }
    if agent == "auditor":
        payload["incident_context"] = {
            "incident_type":      "data_breach",
            "pii_involved":       True,
            "detection_timestamp": "2026-04-07T14:00:00Z",
            "affected_systems":   ["srv-db-01"],
        }

    async with httpx.AsyncClient(timeout=120.0) as c:
        resp = await c.post(f"{url}/jobs", json=payload)
        resp.raise_for_status()
        return resp.json()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent",    required=True,
                        choices=list(AGENT_URLS.keys()))
    parser.add_argument("--mode",     default="continuous")
    parser.add_argument("--tenant",   default="",
                        help="Specific tenant ID (default: all eval tenants)")
    args = parser.parse_args()

    tenants = [args.tenant] if args.tenant else DEFAULT_TENANTS
    url     = AGENT_URLS[args.agent]

    # Health check
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"{url}/health")
            r.raise_for_status()
    except Exception:
        print(f"Agent {args.agent} not responding at {url}")
        print(f"Start it with: docker compose up -d {args.agent.replace('_','-')}-agent")
        sys.exit(1)

    print(f"Triggering {args.agent} ({args.mode}) for {len(tenants)} tenant(s)\n")

    for tenant_id in tenants:
        try:
            result = await trigger(args.agent, args.mode, tenant_id)
            status = result.get("status","?")
            job_id = result.get("job_id","?")[:16]
            print(f"  ✓ {tenant_id:<25} job_id={job_id}… status={status}")
            if result.get("compliance_scores"):
                scores = result["compliance_scores"]
                print(f"      overall={scores.get('overall','?')}  gaps={result.get('gap_count','?')}")
            if result.get("overall_score") is not None:
                print(f"      hackability_score={result['overall_score']}  paths={result.get('attack_paths','?')}")
            if status == "hitl_pending":
                print(f"      → Review at http://localhost:8090")
        except Exception as e:
            print(f"  ✗ {tenant_id}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
