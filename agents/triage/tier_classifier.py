"""
agents/triage/tier_classifier.py — Deterministic tier assignment.

NEVER in the LLM prompt. NEVER in LangGraph routing logic.
The LLM outputs raw signal scores. This function makes the tier decision.
Unchanged at SAO migration.
"""


def classify_tier(assessment: dict) -> tuple[int, str]:
    """
    Returns (tier: int, rationale: str).

    Evaluation order: Tier 3 rules first, top-down. First match wins.
    Tier 1 is the default fallback.

    Args:
        assessment: parsed JSON from LLM response

    Returns:
        (tier, rationale) — tier is 1, 2, or 3
    """
    lm   = bool(assessment.get("lateral_movement_indicators", False))
    sev  = str(assessment.get("severity_assessment", "low")).lower()
    crit = str(assessment.get("asset_criticality",   "standard")).lower()
    nov  = float(assessment.get("novelty_score",   0.0))
    conf = float(assessment.get("confidence",      0.0))
    sig  = bool(assessment.get("known_signature_match", True))

    # ── TIER 3: Page analyst immediately ─────────────────────────────────────
    if lm:
        return 3, f"Lateral movement indicators detected"

    if sev == "critical":
        return 3, f"Severity assessed as critical"

    if crit == "critical" and sev in ("high", "critical"):
        return 3, f"Critical asset with {sev} severity"

    # ── TIER 2: Queue for analyst review ─────────────────────────────────────
    if sev == "high":
        return 2, f"Severity assessed as high"

    if nov > 0.7:
        return 2, f"High novelty score: {nov:.2f} (unknown pattern)"

    if conf < 0.6:
        return 2, f"Low model confidence: {conf:.2f} — insufficient data to auto-resolve"

    if not sig and crit != "standard":
        return 2, f"Unknown signature on {crit} criticality asset"

    # ── TIER 1: Auto-resolve ──────────────────────────────────────────────────
    return 1, f"Low severity, known pattern, confidence {conf:.2f}"


# ── Unit test data ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # (assessment, expected_tier, description)
        ({"lateral_movement_indicators": True,  "severity_assessment": "low"},  3, "LM override"),
        ({"lateral_movement_indicators": False, "severity_assessment": "critical"}, 3, "Critical sev"),
        ({"asset_criticality": "critical", "severity_assessment": "high"}, 3, "Critical asset+high"),
        ({"severity_assessment": "high"}, 2, "High severity"),
        ({"novelty_score": 0.85, "severity_assessment": "low"}, 2, "High novelty"),
        ({"confidence": 0.4, "severity_assessment": "medium"}, 2, "Low confidence"),
        ({"known_signature_match": False, "asset_criticality": "important"}, 2, "Unknown sig on important"),
        ({"severity_assessment": "low", "confidence": 0.9, "known_signature_match": True}, 1, "Tier 1 default"),
    ]

    passed = 0
    for assessment, expected, desc in tests:
        tier, rationale = classify_tier(assessment)
        status = "PASS" if tier == expected else "FAIL"
        print(f"[{status}] {desc}: tier={tier} (expected {expected}) — {rationale}")
        if tier == expected:
            passed += 1

    print(f"\n{passed}/{len(tests)} tests passed")
    if passed < len(tests):
        raise SystemExit(1)
