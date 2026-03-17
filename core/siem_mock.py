"""core/siem_mock.py — MockSIEM for dev and eval. 15 fixture events. Unchanged at migration."""
from __future__ import annotations


# ── Asset profiles ────────────────────────────────────────────────────────────
MOCK_ASSETS = {
    "srv-auth-01": {
        "asset_id": "srv-auth-01", "hostname": "srv-auth-01",
        "ip": "10.10.4.22", "os": "Ubuntu 22.04",
        "criticality": "critical", "data_sensitivity": "high",
        "internet_facing": False, "firewall_protected": True,
        "upstream_firewall": "fw-internal-01",
        "network_segment": "internal", "owner": "identity-team",
        "services": ["LDAP", "Kerberos", "RADIUS"],
        "ncii_sector_relevance": True,
    },
    "srv-db-01": {
        "asset_id": "srv-db-01", "hostname": "srv-db-01",
        "ip": "10.10.3.11", "os": "Ubuntu 22.04",
        "criticality": "critical", "data_sensitivity": "restricted",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "dba-team",
        "services": ["PostgreSQL"], "ncii_sector_relevance": True,
    },
    "srv-web-01": {
        "asset_id": "srv-web-01", "hostname": "srv-web-01",
        "ip": "10.10.1.22", "os": "Ubuntu 22.04",
        "criticality": "important", "data_sensitivity": "medium",
        "internet_facing": True, "firewall_protected": False,
        "network_segment": "DMZ", "owner": "web-team",
        "services": ["nginx", "TLS 1.3"],
    },
    "ws-finance-07": {
        "asset_id": "ws-finance-07", "hostname": "ws-finance-07",
        "ip": "10.10.2.55", "os": "Windows 11",
        "criticality": "important", "data_sensitivity": "high",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "finance-team",
    },
    "ws-dev-03": {
        "asset_id": "ws-dev-03", "hostname": "ws-dev-03",
        "ip": "10.10.6.33", "os": "Ubuntu 22.04",
        "criticality": "standard", "data_sensitivity": "low",
        "internet_facing": False, "firewall_protected": True,
        "network_segment": "internal", "owner": "dev-team",
    },
}

# ── Events ────────────────────────────────────────────────────────────────────
MOCK_EVENTS: dict[str, dict] = {

    # Tier 3 — lateral movement on critical asset
    "lateral-movement-critical": {
        "event_id": "mock-001", "event_type": "lateral_movement_attempt",
        "source_ip": "10.10.4.22", "destination_asset": "srv-db-01",
        "destination_ip": "10.10.3.11", "rule_level": 13, "rule_id": "5720",
        "rule_description": "Lateral movement: successful auth to DB from auth server outside business hours",
        "mitre_techniques": ["T1021", "T1078"], "failure_count": 0,
        "protocol": "TCP/5432", "timestamp": "2026-04-07T02:34:12Z",
    },

    # Tier 3 — brute force on critical asset from external
    "brute-force-critical": {
        "event_id": "mock-002", "event_type": "multiple_failed_logins",
        "source_ip": "203.0.113.42", "destination_asset": "srv-auth-01",
        "destination_ip": "10.10.4.22", "rule_level": 12, "rule_id": "5763",
        "rule_description": "Multiple SSH authentication failures from external IP",
        "mitre_techniques": ["T1110.001"], "failure_count": 47,
        "timespan_seconds": 180, "protocol": "SSH",
        "timestamp": "2026-04-07T14:23:00Z",
    },

    # Tier 3 — ransomware precursor
    "ransomware-precursor": {
        "event_id": "mock-003", "event_type": "ransomware_precursor",
        "source_ip": "10.10.2.55", "destination_asset": "ws-finance-07",
        "rule_level": 14, "rule_id": "87702",
        "rule_description": "Shadow copy deletion detected — ransomware precursor",
        "mitre_techniques": ["T1490", "T1486"],
        "timestamp": "2026-04-07T09:11:00Z",
    },

    # Tier 3 — known malware (Mimikatz)
    "mimikatz-detected": {
        "event_id": "mock-004", "event_type": "malware_detected",
        "source_ip": "10.10.2.55", "destination_asset": "ws-finance-07",
        "rule_level": 14, "rule_id": "60122",
        "rule_description": "Mimikatz credential dumper detected in memory",
        "mitre_techniques": ["T1003.001"],
        "timestamp": "2026-04-07T10:05:00Z",
    },

    # Tier 2 — high severity web attack
    "web-attack-high": {
        "event_id": "mock-005", "event_type": "web_attack",
        "source_ip": "198.51.100.22", "destination_asset": "srv-web-01",
        "rule_level": 10, "rule_id": "31166",
        "rule_description": "SQL injection attempt detected in HTTP request",
        "mitre_techniques": ["T1190"], "protocol": "HTTPS",
        "timestamp": "2026-04-07T11:30:00Z",
    },

    # Tier 2 — CVE exploitation attempt
    "cve-exploitation": {
        "event_id": "mock-006", "event_type": "cve_detected",
        "source_ip": "203.0.113.99", "destination_asset": "srv-web-01",
        "rule_level": 11, "rule_id": "23001",
        "rule_description": "CVE-2024-1234 exploitation attempt detected",
        "mitre_techniques": ["T1190"],
        "cve_id": "CVE-2024-1234",
        "timestamp": "2026-04-07T13:00:00Z",
    },

    # Tier 2 — port scan from external
    "port-scan-external": {
        "event_id": "mock-007", "event_type": "port_scan",
        "source_ip": "198.51.100.22", "destination_asset": "srv-web-01",
        "rule_level": 8, "rule_id": "40101",
        "rule_description": "TCP port scan from external IP — 150 ports in 10s",
        "ports_scanned": 150, "protocol": "TCP",
        "timestamp": "2026-04-07T08:00:00Z",
    },

    # Tier 2 — data exfiltration indicator
    "data-exfiltration": {
        "event_id": "mock-008", "event_type": "data_exfiltration",
        "source_ip": "10.10.3.11", "destination_ip": "203.0.113.100",
        "destination_asset": "srv-db-01", "rule_level": 12, "rule_id": "65001",
        "rule_description": "Anomalous outbound data transfer: 2.3GB to external IP",
        "bytes_transferred": 2300000000, "protocol": "HTTPS",
        "mitre_techniques": ["T1041"],
        "timestamp": "2026-04-07T03:44:00Z",
    },

    # Tier 2 — file integrity violation on critical asset
    "file-integrity-violation": {
        "event_id": "mock-009", "event_type": "file_integrity_violation",
        "destination_asset": "srv-auth-01", "rule_level": 10, "rule_id": "554",
        "rule_description": "Integrity checksum changed: /etc/passwd",
        "changed_file": "/etc/passwd", "mitre_techniques": ["T1098"],
        "timestamp": "2026-04-07T22:15:00Z",
    },

    # Tier 2 — privilege escalation
    "privilege-escalation": {
        "event_id": "mock-010", "event_type": "privilege_escalation",
        "source_ip": "10.10.6.33", "destination_asset": "ws-dev-03",
        "rule_level": 11, "rule_id": "5501",
        "rule_description": "Sudo privilege escalation by non-admin user",
        "mitre_techniques": ["T1548.003"],
        "timestamp": "2026-04-07T15:00:00Z",
    },

    # Tier 2 — DNS tunnelling indicator
    "dns-tunnelling": {
        "event_id": "mock-011", "event_type": "dns_exfiltration",
        "source_ip": "10.10.6.33", "destination_asset": "ws-dev-03",
        "rule_level": 9, "rule_id": "82001",
        "rule_description": "Anomalous DNS query volume — potential tunnelling",
        "queries_per_minute": 450, "mitre_techniques": ["T1071.004"],
        "timestamp": "2026-04-07T16:30:00Z",
    },

    # Tier 1 — known low-level noise
    "low-level-auth-failure": {
        "event_id": "mock-012", "event_type": "failed_login",
        "source_ip": "10.10.6.33", "destination_asset": "ws-dev-03",
        "rule_level": 5, "rule_id": "5710",
        "rule_description": "SSH authentication failure",
        "failure_count": 3, "protocol": "SSH",
        "timestamp": "2026-04-07T09:00:00Z",
    },

    # Tier 1 — standard scheduled scan
    "scheduled-vulnerability-scan": {
        "event_id": "mock-013", "event_type": "port_scan",
        "source_ip": "10.10.100.5", "destination_asset": "srv-web-01",
        "rule_level": 6, "rule_id": "40102",
        "rule_description": "Vulnerability scan from known scanner (Nessus)",
        "known_scanner": True, "protocol": "TCP",
        "timestamp": "2026-04-07T02:00:00Z",
    },

    # Tier 2 — OJK-relevant financial sector event
    "financial-system-anomaly": {
        "event_id": "mock-014", "event_type": "anomalous_access",
        "source_ip": "10.10.2.55", "destination_asset": "srv-db-01",
        "rule_level": 10, "rule_id": "65101",
        "rule_description": "Anomalous access to financial transaction table outside business hours",
        "mitre_techniques": ["T1078"],
        "ncii_relevant": True, "ojk_reportable": True,
        "timestamp": "2026-04-07T01:30:00Z",
    },

    # Tier 3 — APT indicators (BSSN concern)
    "apt-indicator": {
        "event_id": "mock-015", "event_type": "apt_indicator",
        "source_ip": "203.0.113.200", "destination_asset": "srv-auth-01",
        "rule_level": 15, "rule_id": "91001",
        "rule_description": "APT indicator: beaconing pattern matches known state-actor C2",
        "mitre_techniques": ["T1071.001", "T1573", "T1041"],
        "confidence": 0.87,
        "bssn_reportable": True,
        "timestamp": "2026-04-07T04:12:00Z",
    },
}

# ── Threat intel ──────────────────────────────────────────────────────────────
MOCK_THREAT_INTEL = {
    "203.0.113.42":  {"reputation": "malicious",  "confidence": 0.91,
                      "ttps": ["T1110.001", "T1078"], "campaigns": ["APT-Scatter-2024"]},
    "198.51.100.22": {"reputation": "suspicious",  "confidence": 0.65,
                      "ttps": ["T1190"],            "campaigns": []},
    "203.0.113.99":  {"reputation": "malicious",  "confidence": 0.88,
                      "ttps": ["T1190"],            "campaigns": ["Void-Rabisu"]},
    "203.0.113.200": {"reputation": "malicious",  "confidence": 0.93,
                      "ttps": ["T1071.001", "T1573"], "campaigns": ["APT-ID-State-Actor"]},
}


class MockSIEM:
    """Drop-in replacement for WazuhAdapter in dev and eval."""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    async def get_event_history(
        self, tenant_id: str, asset_id: str,
        event_type: str | None = None, lookback_hours: int = 24,
    ) -> dict:
        matching = [
            e for e in MOCK_EVENTS.values()
            if e.get("destination_asset") == asset_id
               and (event_type is None or e.get("event_type") == event_type)
        ]
        return {"asset_id": asset_id, "events": matching, "count": len(matching)}

    async def get_asset_profile(self, tenant_id: str, asset_id: str) -> dict:
        return MOCK_ASSETS.get(asset_id, {
            "asset_id": asset_id, "hostname": asset_id,
            "ip": "10.10.0.0", "criticality": "standard",
            "data_sensitivity": "low", "internet_facing": False,
            "firewall_protected": True,
        })

    async def get_threat_intel(
        self, tenant_id: str, ioc_value: str, ioc_type: str,
    ) -> dict:
        return MOCK_THREAT_INTEL.get(ioc_value, {
            "reputation": "unknown", "confidence": 0.0, "ttps": [], "campaigns": [],
        })
