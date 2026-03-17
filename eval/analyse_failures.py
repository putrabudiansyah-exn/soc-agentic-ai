#!/usr/bin/env python3
"""
eval/analyse_failures.py — Failure analysis for prompt iteration.
Reads runner output and tells you exactly which prompt section to fix.

Usage:
  python eval/analyse_failures.py --results eval/baselines/ID_latest.json
"""

import argparse, json, sys
from pathlib import Path


def analyse(results: list[dict]) -> dict:
    failures  = [r for r in results if not r["tier_match"]]
    under     = [r for r in failures if r["actual_tier"] < r["expected_tier"]]
    over      = [r for r in failures if r["actual_tier"] > r["expected_tier"]]
    missed_t3 = [r for r in under   if r["expected_tier"] == 3]

    # Pattern clustering on missed Tier 3 (most critical failure mode)
    patterns = {"high_conf_miss":0, "low_conf_force_t2":0, "mid_conf_miss":0}
    for r in missed_t3:
        c = float(r.get("confidence", 0))
        if c >= 0.8:   patterns["high_conf_miss"]    += 1
        elif c < 0.6:  patterns["low_conf_force_t2"] += 1
        else:          patterns["mid_conf_miss"]      += 1

    return {
        "total_failures": len(failures),
        "under_escalated":len(under),
        "over_escalated": len(over),
        "missed_tier3":   len(missed_t3),
        "patterns":       patterns,
        "samples":        failures[:5],
    }


def print_hints(analysis: dict):
    missed = analysis["missed_tier3"]
    if not missed:
        return
    patterns = analysis["patterns"]
    total    = missed or 1

    print("\nPROMPT FIX HINTS:")
    if patterns["high_conf_miss"] / total > 0.5:
        print("  → LLM is confident but wrong.")
        print("    Fix: Tighten severity conditions in [OUTPUT FORMAT] section.")
        print("    E.g. Make 'critical' severity conditions more specific.")

    if patterns["low_conf_force_t2"] / total > 0.5:
        print("  → Low confidence is causing Tier 2 when Tier 3 expected.")
        print("    Fix: Check [CONFIDENCE CALIBRATION] — is model under-confident on clear signals?")
        print("    Consider: tool data should raise confidence, not lower it.")

    if patterns["mid_conf_miss"] / total > 0.5:
        print("  → Mid-range confidence misses: model is uncertain on Tier 3 events.")
        print("    Fix: Add more specific Tier 3 signal criteria to [OUTPUT FORMAT].")
        print("    E.g. Explicit list of ransomware precursor patterns.")

    if analysis["over_escalated"] > analysis["under_escalated"]:
        print("  → Over-escalation (Tier 2 when Tier 1 expected).")
        print("    Fix: Tighten 'high' severity conditions. Add 'known_scanner' exclusions.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    args = parser.parse_args()

    data    = json.loads(Path(args.results).read_text())
    results = data.get("results", [])
    metrics = data.get("metrics", {})

    analysis = analyse(results)

    print("FAILURE ANALYSIS")
    print("═" * 50)
    print(f"Total fixtures:    {len(results)}")
    print(f"Total failures:    {analysis['total_failures']} ({analysis['total_failures']*100//max(len(results),1)}%)")
    print(f"Under-escalated:   {analysis['under_escalated']}")
    print(f"Over-escalated:    {analysis['over_escalated']}")
    print(f"Missed Tier 3:     {analysis['missed_tier3']}  ← CRITICAL")
    print(f"Failure patterns:  {analysis['patterns']}")

    if analysis["samples"]:
        print("\nSample failures (first 5):")
        for r in analysis["samples"]:
            print(f"  {r['fixture_file']}: expected=T{r['expected_tier']} "
                  f"actual=T{r['actual_tier']} conf={r['confidence']:.2f}")

    print_hints(analysis)

    print(f"\nCurrent tier accuracy: {metrics.get('tier_accuracy',0):.1%}")
    gap = 0.92 - metrics.get('tier_accuracy', 0)
    if gap > 0:
        needed = int(gap * len(results))
        print(f"Need {needed} more correct to reach 92% gate.")
    else:
        print("✓ Gate already passing — focus on false negative rate if still failing.")


if __name__ == "__main__":
    main()
