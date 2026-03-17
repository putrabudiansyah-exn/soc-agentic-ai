#!/usr/bin/env python3
"""
scripts/run_event.py — Run a single security event through the Triage Agent locally.
Useful for debugging before running the full eval suite.

Usage:
  # From a fixture file:
  python scripts/run_event.py --event-file eval/fixtures/ID/gen-abc123.json

  # From a MockSIEM event name:
  python scripts/run_event.py --mock-event brute-force-critical --tenant-id eval-tenant-id

  # Quick test with inline JSON:
  python scripts/run_event.py --json '{"event_id":"test","event_type":"port_scan","rule_level":8}'
"""

import argparse, asyncio, json, os, sys, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

import httpx


async def run_via_api(event: dict, tenant_id: str, agent_url: str) -> dict:
    """Submit event to running Triage Agent via HTTP."""
    job_id = str(uuid.uuid4())
    async with httpx.AsyncClient(timeout=60.0) as c:
        resp = await c.post(f"{agent_url}/jobs", json={
            "job_id":       job_id,
            "tenant_id":    tenant_id,
            "department_id":f"soc-{tenant_id}",
            "input":        event,
        })
        resp.raise_for_status()
        return resp.json()


async def run_direct(event: dict, tenant_id: str) -> dict:
    """Run graph directly without HTTP (for deep debugging)."""
    from agents.triage.graph import build_triage_graph, TriageState
    from core.tenant_registry import get_jurisdiction

    graph = await build_triage_graph()
    job_id = str(uuid.uuid4())

    initial_state: TriageState = {
        "job_id":         job_id,
        "department_id":  f"soc-{tenant_id}",
        "tenant_id":      tenant_id,
        "jurisdiction":   get_jurisdiction(tenant_id),
        "event":          event,
        "messages":       [],
        "tool_call_count":0,
        "opa_denials":    0,
        "budget_status":  "OK",
        "_retry_count":   0,
        "assessment":     None,
        "tier":           None,
        "tier_rationale": None,
        "hitl_required":  False,
        "auto_resolved":  False,
        "quality_signal_emitted": False,
    }
    config = {"configurable": {"thread_id": job_id}}
    await graph.ainvoke(initial_state, config=config)
    snapshot = await graph.aget_state(config)
    state    = snapshot.values
    return {
        "job_id":        job_id,
        "tier":          state.get("tier"),
        "tier_rationale":state.get("tier_rationale"),
        "assessment":    state.get("assessment"),
        "hitl_required": state.get("hitl_required"),
        "auto_resolved": state.get("auto_resolved"),
        "tool_call_count":state.get("tool_call_count"),
        "opa_denials":   state.get("opa_denials"),
    }


def print_result(result: dict):
    tier    = result.get("tier", 0)
    hitl    = result.get("hitl_required", False)
    auto    = result.get("auto_resolved",  False)
    rationale = result.get("tier_rationale", "")
    assessment = result.get("assessment", {}) or {}

    tier_labels = {1:"🟢 Auto-resolve", 2:"🟡 HITL queue", 3:"🔴 Page analyst"}
    print(f"\n{'═'*56}")
    print(f"  RESULT")
    print(f"{'═'*56}")
    print(f"  Tier:          {tier}  {tier_labels.get(tier,'')}")
    print(f"  Rationale:     {rationale}")
    print(f"  HITL required: {hitl}")
    print(f"  Auto-resolved: {auto}")
    print(f"  Tool calls:    {result.get('tool_call_count',0)}/3")
    if assessment:
        print(f"\n  Assessment:")
        print(f"    severity:  {assessment.get('severity_assessment','?')}")
        print(f"    confidence:{assessment.get('confidence',0):.2f}")
        print(f"    novelty:   {assessment.get('novelty_score',0):.2f}")
        print(f"    lateral:   {assessment.get('lateral_movement_indicators','?')}")
        print(f"    summary:   {assessment.get('summary','')}")
    print(f"{'═'*56}\n")


async def main():
    parser = argparse.ArgumentParser(description="Run a single event through the Triage Agent")
    parser.add_argument("--event-file",  help="Path to fixture JSON file")
    parser.add_argument("--mock-event",  help="Name of MockSIEM event (see core/siem_mock.py)")
    parser.add_argument("--json",        help="Inline event JSON string")
    parser.add_argument("--tenant-id",   default="eval-tenant-id")
    parser.add_argument("--agent-url",   default="http://localhost:8080",
                        help="Agent URL (use 'direct' to skip HTTP)")
    args = parser.parse_args()

    # Load event
    if args.event_file:
        fixture = json.loads(Path(args.event_file).read_text())
        event   = fixture.get("input", fixture)
        print(f"Loaded fixture: {args.event_file}")
    elif args.mock_event:
        from core.siem_mock import MOCK_EVENTS
        if args.mock_event not in MOCK_EVENTS:
            print(f"Unknown mock event. Available: {list(MOCK_EVENTS.keys())}")
            sys.exit(1)
        event = MOCK_EVENTS[args.mock_event]
        event["tenant_id"] = args.tenant_id
        print(f"Loaded mock event: {args.mock_event}")
    elif args.json:
        event = json.loads(args.json)
        print(f"Loaded inline event")
    else:
        parser.print_help()
        sys.exit(1)

    print(f"Tenant:   {args.tenant_id}")
    print(f"Event ID: {event.get('event_id','—')}")
    print(f"Type:     {event.get('event_type','—')}")
    print(f"Asset:    {event.get('destination_asset','—')}")
    print(f"Submitting…")

    if args.agent_url == "direct":
        result = await run_direct(event, args.tenant_id)
    else:
        try:
            result = await run_via_api(event, args.tenant_id, args.agent_url)
        except httpx.ConnectError:
            print(f"\nCannot connect to agent at {args.agent_url}")
            print("Is it running? Try: docker compose up -d  OR  uvicorn agents.triage.main:app")
            print("Or use --agent-url direct to run without HTTP.")
            sys.exit(1)

    print_result(result)

if __name__ == "__main__":
    asyncio.run(main())
