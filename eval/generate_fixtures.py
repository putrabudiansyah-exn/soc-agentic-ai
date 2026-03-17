#!/usr/bin/env python3
"""
eval/generate_fixtures.py — Auto-generates eval fixtures from Wazuh rule library.
Covers Source A (automated generation) of the three-source fixture strategy.

Usage:
  python eval/generate_fixtures.py --jurisdiction ID --output eval/fixtures/ID --count 60
  python eval/generate_fixtures.py --jurisdiction MY --output eval/fixtures/MY --count 60
"""

import argparse, json, random, sys, uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.triage.tier_classifier import classify_tier


# ── Wazuh rule library subset ─────────────────────────────────────────────────
WAZUH_RULES = [
    # level, groups, description, mitre_techniques
    # Tier 3 generators
    {"level":15,"groups":["ransomware"],"desc":"Ransomware: volume shadow copy deletion detected","mitre":["T1490"]},
    {"level":15,"groups":["malware"],"desc":"Mimikatz credential dumper in memory","mitre":["T1003.001"]},
    {"level":14,"groups":["ransomware"],"desc":"Mass file encryption activity detected","mitre":["T1486"]},
    {"level":14,"groups":["malware","apt"],"desc":"APT beaconing pattern to known C2","mitre":["T1071.001","T1573"]},
    {"level":13,"groups":["authentication_failed","lateral"],"desc":"Lateral movement via stolen credentials","mitre":["T1021","T1078"]},
    {"level":12,"groups":["authentication_failed"],"desc":"50 SSH auth failures in 3 min from external IP","mitre":["T1110.001"]},
    # Tier 2 generators
    {"level":11,"groups":["vulnerability-detector"],"desc":"CVE-2024-1234 exploitation attempt","mitre":["T1190"]},
    {"level":11,"groups":["privilege"],"desc":"Sudo privilege escalation by non-admin user","mitre":["T1548.003"]},
    {"level":10,"groups":["web-attack"],"desc":"SQL injection confirmed in HTTP request body","mitre":["T1190"]},
    {"level":10,"groups":["syscheck"],"desc":"Critical file modified: /etc/passwd","mitre":["T1098"]},
    {"level":10,"groups":["network"],"desc":"Anomalous outbound data 2.3GB to external IP","mitre":["T1041"]},
    {"level":9,"groups":["dns"],"desc":"DNS tunnelling: 450 queries/min","mitre":["T1071.004"]},
    {"level":9,"groups":["network_scan"],"desc":"TCP port scan 150 ports in 10s","mitre":["T1046"]},
    {"level":8,"groups":["authentication_failed"],"desc":"20 RDP login failures on server","mitre":["T1110"]},
    # Tier 1 generators
    {"level":7,"groups":["authentication_failed"],"desc":"SSH authentication failure (single)","mitre":[]},
    {"level":6,"groups":["network_scan"],"desc":"Nessus vulnerability scan from known scanner","mitre":[]},
    {"level":5,"groups":["authentication_failed"],"desc":"3 failed logins — below threshold","mitre":[]},
]

ASSET_PROFILES = [
    {"hostname":"srv-auth-01","ip":"10.10.4.22","criticality":"critical","internet_facing":False},
    {"hostname":"srv-db-01","ip":"10.10.3.11","criticality":"critical","internet_facing":False},
    {"hostname":"srv-web-01","ip":"10.10.1.22","criticality":"important","internet_facing":True},
    {"hostname":"ws-finance-07","ip":"10.10.2.55","criticality":"important","internet_facing":False},
    {"hostname":"ws-dev-03","ip":"10.10.6.33","criticality":"standard","internet_facing":False},
    {"hostname":"ws-hr-04","ip":"10.10.2.10","criticality":"standard","internet_facing":False},
]

EXTERNAL_IPS = ["203.0.113.42","198.51.100.22","203.0.113.99","198.51.100.77","203.0.113.200"]
INTERNAL_IPS = ["10.10.4.22","10.10.3.11","10.10.2.55","10.10.6.33"]


def derive_assessment(rule: dict, asset: dict) -> dict:
    """Simulate what a well-calibrated LLM should return for this event."""
    level = rule["level"]
    is_lateral = "lateral" in rule["groups"]
    is_critical = asset["criticality"] == "critical"
    is_important = asset["criticality"] == "important"

    if level >= 13 or is_lateral:
        severity = "critical"; conf = 0.91; nov = 0.8
    elif level >= 11 and is_critical:
        severity = "critical"; conf = 0.85; nov = 0.6
    elif level >= 10:
        severity = "high"; conf = 0.82; nov = 0.5
    elif level >= 8:
        severity = "medium"; conf = 0.75; nov = 0.3
    else:
        severity = "low"; conf = 0.88; nov = 0.1

    return {
        "severity_assessment":         severity,
        "novelty_score":               round(nov + random.uniform(-0.1,0.1), 2),
        "lateral_movement_indicators": is_lateral,
        "asset_criticality":           asset["criticality"],
        "known_signature_match":       level < 13,
        "confidence":                  round(conf + random.uniform(-0.05,0.05), 2),
    }


def generate_fixture(rule: dict, asset: dict, jurisdiction: str, tenant_id: str) -> dict:
    assessment  = derive_assessment(rule, asset)
    tier, _     = classify_tier(assessment)
    event_id    = f"gen-{uuid.uuid4().hex[:8]}"
    source_ip   = random.choice(EXTERNAL_IPS) if asset["internet_facing"] else random.choice(INTERNAL_IPS)

    return {
        "input": {
            "event_id":          event_id,
            "event_type":        rule["groups"][0].replace("-","_"),
            "source_ip":         source_ip,
            "destination_asset": asset["hostname"],
            "destination_ip":    asset["ip"],
            "rule_level":        rule["level"],
            "rule_description":  rule["desc"],
            "mitre_techniques":  rule["mitre"],
            "tenant_id":         tenant_id,
        },
        "expected": {
            "tier":                  tier,
            "severity":              assessment["severity_assessment"],
            "lateral_movement":      assessment["lateral_movement_indicators"],
            "annotator":             "automated_wazuh_rule",
            "jurisdiction":          jurisdiction,
            "annotation_date":       "2026-04-07",
            "confidence_in_label":   0.85,
            "notes":                 f"rule_level={rule['level']}, asset={asset['criticality']}",
        },
        "_debug_assessment": assessment,  # for fixture review — not used by runner
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jurisdiction", choices=["ID","MY","DE"], default="ID")
    parser.add_argument("--output", default="eval/fixtures/ID")
    parser.add_argument("--count", type=int, default=60)
    args = parser.parse_args()

    out_dir   = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    tenant_id = f"eval-tenant-{args.jurisdiction.lower()}"

    fixtures = []
    for i in range(args.count):
        rule  = random.choice(WAZUH_RULES)
        asset = random.choice(ASSET_PROFILES)
        f     = generate_fixture(rule, asset, args.jurisdiction, tenant_id)
        filepath = out_dir / f"{f['input']['event_id']}.json"
        filepath.write_text(json.dumps(f, indent=2))
        fixtures.append(f)

    # Print tier distribution
    dist = {1:0, 2:0, 3:0}
    for f in fixtures:
        dist[f["expected"]["tier"]] += 1

    print(f"Generated {args.count} fixtures → {out_dir}")
    print(f"Tier distribution: T1={dist[1]} ({dist[1]*100//args.count}%)  "
          f"T2={dist[2]} ({dist[2]*100//args.count}%)  "
          f"T3={dist[3]} ({dist[3]*100//args.count}%)")
    print(f"Next: label adversarial fixtures manually, then run:")
    print(f"  python eval/runner.py --jurisdiction {args.jurisdiction}")


if __name__ == "__main__":
    main()
