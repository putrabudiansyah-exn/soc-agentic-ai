#!/usr/bin/env python3
"""
eval/runner.py — Eval pipeline runner.
Submits fixtures through the live agent and records results.
Unchanged at SAO migration (just points to the same agent endpoint).

Usage:
  python eval/runner.py --jurisdiction ID
  python eval/runner.py --jurisdiction MY --agent-url http://localhost:8080
"""

import argparse, asyncio, json, sys, time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))


async def submit_event(
    event: dict, tenant_id: str, agent_url: str
) -> dict:
    """Submit one event and poll for result. Timeout 60s."""
    import uuid
    job_id = str(uuid.uuid4())

    async with httpx.AsyncClient(timeout=10.0) as c:
        resp = await c.post(f"{agent_url}/jobs", json={
            "job_id":       job_id,
            "tenant_id":    tenant_id,
            "department_id":"soc-eval",
            "input":        event,
        })
        resp.raise_for_status()
        result = resp.json()

    return result


async def run_eval(
    jurisdiction: str,
    agent_url:    str,
    fixtures_dir: Path,
    max_fixtures: int = 0,
) -> list[dict]:
    fixtures = list(fixtures_dir.glob("*.json"))
    if max_fixtures:
        fixtures = fixtures[:max_fixtures]
    if not fixtures:
        print(f"No fixtures found in {fixtures_dir}. Run generate_fixtures.py first.")
        return []

    tenant_id = f"eval-tenant-{jurisdiction.lower()}"
    results   = []
    errors    = 0

    print(f"Running eval: {len(fixtures)} fixtures, jurisdiction={jurisdiction}")
    print("─" * 60)

    for i, fp in enumerate(fixtures, 1):
        fixture = json.loads(fp.read_text())
        event   = fixture["input"]
        expected= fixture["expected"]

        try:
            t0     = time.monotonic()
            result = await submit_event(event, tenant_id, agent_url)
            elapsed= round((time.monotonic() - t0) * 1000)

            actual_tier = result.get("tier") or 0
            tier_match  = actual_tier == expected["tier"]
            false_neg   = expected["tier"] == 3 and actual_tier < 3

            rec = {
                "fixture_id":    event["event_id"],
                "fixture_file":  fp.name,
                "expected_tier": expected["tier"],
                "actual_tier":   actual_tier,
                "tier_match":    tier_match,
                "false_negative":false_neg,
                "confidence":    result.get("assessment", {}).get("confidence", 0) if result.get("assessment") else 0,
                "hitl_required": result.get("hitl_required", False),
                "latency_ms":    elapsed,
                "status":        result.get("status", "unknown"),
            }
            results.append(rec)

            status_char = "✓" if tier_match else ("⚠" if false_neg else "✗")
            print(f"[{i:3}/{len(fixtures)}] {status_char} "
                  f"expected=T{expected['tier']} actual=T{actual_tier} "
                  f"{elapsed}ms  {fp.name}")

        except Exception as e:
            errors += 1
            print(f"[{i:3}/{len(fixtures)}] ERROR: {e}")
            results.append({
                "fixture_id": event["event_id"],
                "fixture_file": fp.name,
                "expected_tier": expected["tier"],
                "actual_tier": 0,
                "tier_match": False,
                "false_negative": expected["tier"] == 3,
                "confidence": 0,
                "hitl_required": False,
                "latency_ms": 0,
                "status": "error",
                "error": str(e),
            })

    return results


def calculate_metrics(results: list[dict]) -> dict:
    if not results:
        return {}
    total   = len(results)
    t3_total= sum(1 for r in results if r["expected_tier"] == 3)
    return {
        "total_fixtures":       total,
        "tier_accuracy":        round(sum(1 for r in results if r["tier_match"]) / total, 4),
        "false_negative_rate":  round(sum(1 for r in results if r["false_negative"]) / max(t3_total, 1), 4),
        "hitl_rate":            round(sum(1 for r in results if r.get("hitl_required")) / total, 4),
        "avg_latency_ms":       round(sum(r["latency_ms"] for r in results) / total),
        "error_count":          sum(1 for r in results if r.get("status") == "error"),
        "tier_distribution":    {
            f"tier_{t}": sum(1 for r in results if r["expected_tier"] == t)
            for t in (1,2,3)
        },
    }


def check_gates(metrics: dict) -> list[str]:
    """Return list of gate failures. Empty list = all gates pass."""
    failures = []
    if metrics.get("tier_accuracy", 0) < 0.92:
        failures.append(
            f"GATE FAIL: tier_accuracy={metrics['tier_accuracy']:.3f} < 0.92 required"
        )
    if metrics.get("false_negative_rate", 1) >= 0.01:
        failures.append(
            f"GATE FAIL: false_negative_rate={metrics['false_negative_rate']:.3f} >= 0.01 limit"
        )
    if metrics.get("error_count", 0) > 0:
        failures.append(
            f"GATE FAIL: {metrics['error_count']} fixture errors"
        )
    return failures


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jurisdiction", choices=["ID","MY","DE"], default="ID")
    parser.add_argument("--agent-url",    default="http://localhost:8080")
    parser.add_argument("--fixtures-dir", default="")
    parser.add_argument("--output",       default="")
    parser.add_argument("--max",          type=int, default=0, help="Limit fixtures (for quick runs)")
    args = parser.parse_args()

    fixtures_dir = Path(args.fixtures_dir) if args.fixtures_dir \
                   else Path(__file__).parent / "fixtures" / args.jurisdiction

    results = await run_eval(
        jurisdiction = args.jurisdiction,
        agent_url    = args.agent_url,
        fixtures_dir = fixtures_dir,
        max_fixtures = args.max,
    )

    metrics  = calculate_metrics(results)
    failures = check_gates(metrics)

    print("\n" + "═" * 60)
    print("EVAL RESULTS")
    print("═" * 60)
    print(f"Jurisdiction:       {args.jurisdiction}")
    print(f"Fixtures run:       {metrics.get('total_fixtures',0)}")
    print(f"Tier accuracy:      {metrics.get('tier_accuracy',0):.1%}  (gate: >= 92%)")
    print(f"False negative rate:{metrics.get('false_negative_rate',0):.1%} (gate: < 1%)")
    print(f"HITL rate:          {metrics.get('hitl_rate',0):.1%}")
    print(f"Avg latency:        {metrics.get('avg_latency_ms',0)}ms")
    print(f"Tier distribution:  {metrics.get('tier_distribution',{})}")

    if failures:
        print("\n⚠  GATES FAILED:")
        for f in failures: print(f"   {f}")
    else:
        print("\n✓  All gates passed.")

    # Save results
    output_path = Path(args.output) if args.output \
                  else Path(__file__).parent / "baselines" / f"{args.jurisdiction}_latest.json"
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(json.dumps({
        "metrics": metrics, "results": results, "failures": failures
    }, indent=2))
    print(f"\nResults saved: {output_path}")

    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    asyncio.run(main())
