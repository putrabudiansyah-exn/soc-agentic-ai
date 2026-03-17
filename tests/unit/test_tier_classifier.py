"""
tests/unit/test_tier_classifier.py — Unit tests for the tier classifier.

Run: pytest tests/unit/test_tier_classifier.py -v
All tests must pass before ANY prompt changes are deployed.
The tier classifier must be deterministic — same input always same output.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from agents.triage.tier_classifier import classify_tier


# ── Tier 3 tests — highest priority ──────────────────────────────────────────

class TestTier3:
    def test_lateral_movement_overrides_all(self):
        """Lateral movement always Tier 3, regardless of other signals."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": True,
            "severity_assessment":         "low",
            "asset_criticality":           "standard",
            "confidence":                  0.95,
        })
        assert tier == 3

    def test_lateral_movement_with_low_confidence(self):
        """Lateral movement still Tier 3 even if model has low confidence."""
        tier, rationale = classify_tier({
            "lateral_movement_indicators": True,
            "confidence":                  0.3,
        })
        assert tier == 3
        assert "lateral" in rationale.lower()

    def test_critical_severity(self):
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "critical",
            "asset_criticality":           "standard",
        })
        assert tier == 3

    def test_critical_asset_high_severity(self):
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "high",
            "asset_criticality":           "critical",
        })
        assert tier == 3

    def test_critical_asset_critical_severity(self):
        tier, _ = classify_tier({
            "severity_assessment": "critical",
            "asset_criticality":   "critical",
        })
        assert tier == 3

    def test_critical_asset_medium_severity_is_tier2(self):
        """Critical asset + medium severity should NOT be Tier 3."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "medium",
            "asset_criticality":           "critical",
            "confidence":                  0.9,
        })
        assert tier == 2  # high enough for HITL but not page-immediately


# ── Tier 2 tests ──────────────────────────────────────────────────────────────

class TestTier2:
    def test_high_severity(self):
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "high",
            "asset_criticality":           "standard",
            "confidence":                  0.85,
        })
        assert tier == 2

    def test_high_novelty(self):
        tier, rationale = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "medium",
            "novelty_score":               0.85,
            "confidence":                  0.80,
        })
        assert tier == 2
        assert "novelty" in rationale.lower()

    def test_novelty_exactly_at_threshold(self):
        """novelty_score of exactly 0.7 should NOT trigger Tier 2 (must be > 0.7)."""
        tier, _ = classify_tier({
            "severity_assessment": "low",
            "novelty_score":       0.70,
            "confidence":          0.85,
            "known_signature_match": True,
        })
        assert tier == 1

    def test_novelty_just_above_threshold(self):
        tier, _ = classify_tier({
            "severity_assessment": "low",
            "novelty_score":       0.71,
            "confidence":          0.85,
        })
        assert tier == 2

    def test_low_confidence(self):
        tier, rationale = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "medium",
            "confidence":                  0.45,
        })
        assert tier == 2
        assert "confidence" in rationale.lower()

    def test_confidence_exactly_at_threshold(self):
        """confidence of exactly 0.6 should NOT trigger Tier 2."""
        tier, _ = classify_tier({
            "severity_assessment": "low",
            "confidence":          0.60,
            "novelty_score":       0.3,
            "known_signature_match": True,
        })
        assert tier == 1

    def test_confidence_just_below_threshold(self):
        tier, _ = classify_tier({
            "severity_assessment": "low",
            "confidence":          0.59,
        })
        assert tier == 2

    def test_unknown_signature_important_asset(self):
        tier, _ = classify_tier({
            "severity_assessment":   "low",
            "confidence":            0.8,
            "known_signature_match": False,
            "asset_criticality":     "important",
            "novelty_score":         0.4,
        })
        assert tier == 2

    def test_unknown_signature_standard_asset_is_tier1(self):
        """Unknown signature on standard asset does NOT trigger Tier 2."""
        tier, _ = classify_tier({
            "severity_assessment":   "low",
            "confidence":            0.85,
            "known_signature_match": False,
            "asset_criticality":     "standard",
            "novelty_score":         0.3,
        })
        assert tier == 1


# ── Tier 1 tests ──────────────────────────────────────────────────────────────

class TestTier1:
    def test_clean_low_severity(self):
        tier, rationale = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "low",
            "asset_criticality":           "standard",
            "novelty_score":               0.1,
            "confidence":                  0.92,
            "known_signature_match":       True,
        })
        assert tier == 1
        assert "auto" in rationale.lower() or "tier 1" in rationale.lower() or "low" in rationale.lower()

    def test_medium_severity_high_confidence_known_standard(self):
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "medium",
            "asset_criticality":           "standard",
            "novelty_score":               0.2,
            "confidence":                  0.82,
            "known_signature_match":       True,
        })
        assert tier == 1


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_assessment(self):
        """Empty dict defaults to Tier 1 (low severity, known pattern)."""
        tier, _ = classify_tier({})
        assert tier == 1

    def test_missing_lateral_movement_defaults_false(self):
        """Missing lateral_movement_indicators defaults to False."""
        tier, _ = classify_tier({"severity_assessment": "critical"})
        assert tier == 3   # still Tier 3 due to critical severity

    def test_string_confidence(self):
        """Float conversion should handle edge cases."""
        tier, _ = classify_tier({"confidence": "0.45", "severity_assessment": "low"})
        assert tier == 2

    def test_tier3_before_tier2_rules(self):
        """Verify Tier 3 rules are evaluated before Tier 2."""
        tier, rationale = classify_tier({
            "lateral_movement_indicators": True,   # T3
            "confidence":                  0.4,    # would also be T2
            "severity_assessment":         "high", # would also be T2
        })
        assert tier == 3
        assert "lateral" in rationale.lower()

    def test_rationale_always_populated(self):
        """Rationale must always be a non-empty string."""
        for assessment in [
            {},
            {"lateral_movement_indicators": True},
            {"severity_assessment": "critical"},
            {"severity_assessment": "low", "confidence": 0.95},
        ]:
            tier, rationale = classify_tier(assessment)
            assert isinstance(rationale, str)
            assert len(rationale) > 0, f"Empty rationale for {assessment}"

    def test_deterministic(self):
        """Same input always produces same output."""
        assessment = {
            "severity_assessment": "high",
            "confidence": 0.75,
            "novelty_score": 0.6,
            "lateral_movement_indicators": False,
            "asset_criticality": "important",
        }
        results = [classify_tier(assessment) for _ in range(10)]
        assert all(r == results[0] for r in results), "Non-deterministic output"


# ── Regulatory scenario tests (ID-specific) ───────────────────────────────────

class TestIndonesiaScenarios:
    """Scenarios from Indonesian regulatory context that must produce correct tiers."""

    def test_ojk_financial_system_anomaly(self):
        """OJK-relevant event on important asset → at minimum Tier 2."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "high",
            "asset_criticality":           "important",
            "confidence":                  0.82,
            "novelty_score":               0.3,
        })
        assert tier >= 2

    def test_bssn_apt_indicator_critical_asset(self):
        """APT indicator on critical NCII asset → Tier 3."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "critical",
            "asset_criticality":           "critical",
            "confidence":                  0.87,
        })
        assert tier == 3

    def test_pdp_data_exfiltration_indicator(self):
        """Data exfiltration on critical asset → Tier 3."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "high",
            "asset_criticality":           "critical",  # DB server
            "confidence":                  0.75,
        })
        assert tier == 3

    def test_known_low_level_noise(self):
        """Single SSH auth failure → Tier 1."""
        tier, _ = classify_tier({
            "lateral_movement_indicators": False,
            "severity_assessment":         "low",
            "asset_criticality":           "standard",
            "novelty_score":               0.05,
            "confidence":                  0.95,
            "known_signature_match":       True,
        })
        assert tier == 1
