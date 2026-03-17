#!/usr/bin/env python3
"""
pipeline/wazuh_to_queue.py
Called by Wazuh Active Response when rule level >= 7.
Install at: /var/ossec/integrations/custom-redis-stream
Configure in: /var/ossec/etc/ossec.conf

<integration>
  <name>custom-redis-stream</name>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
"""

import json, os, sys
import redis


def infer_event_type(alert: dict) -> str:
    groups = alert.get("rule", {}).get("groups", [])
    rule_desc = alert.get("rule", {}).get("description", "").lower()
    if "authentication_failed" in groups: return "multiple_failed_logins"
    if "web-attack"            in groups: return "web_attack"
    if "malware"               in groups: return "malware_detected"
    if "ransomware"            in groups: return "ransomware_precursor"
    if "vulnerability-detector"in groups: return "cve_detected"
    if "syscheck"              in groups: return "file_integrity_violation"
    if "network_scan"          in groups: return "port_scan"
    if "lateral"                in rule_desc: return "lateral_movement_attempt"
    if "exfiltration"           in rule_desc: return "data_exfiltration"
    return "generic_security_event"


def sanitise_event(alert: dict, tenant_id: str) -> dict:
    """Strip raw log. Keep only structured fields. Never pass raw_log to LLM."""
    return {
        "event_id":          alert.get("id"),
        "timestamp":         alert.get("timestamp"),
        "tenant_id":         tenant_id,
        "rule_id":           alert.get("rule", {}).get("id"),
        "rule_level":        int(alert.get("rule", {}).get("level", 0)),
        "rule_description":  alert.get("rule", {}).get("description"),
        "event_type":        infer_event_type(alert),
        "source_ip":         alert.get("data", {}).get("srcip"),
        "destination_asset": alert.get("agent", {}).get("name"),
        "destination_ip":    alert.get("agent", {}).get("ip"),
        "protocol":          alert.get("data", {}).get("protocol"),
        "failure_count":     alert.get("data", {}).get("dstuser_count"),
        "mitre_tactics":     alert.get("rule", {}).get("mitre", {}).get("tactic", []),
        "mitre_techniques":  alert.get("rule", {}).get("mitre", {}).get("id", []),
        # raw_log intentionally excluded — never passes to LLM
    }


def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    alert_file = sys.argv[1]
    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception:
        sys.exit(0)

    # tenant_id from Wazuh agent group label — set during client onboarding
    agent_labels = alert.get("agent", {}).get("labels", {})
    tenant_id    = agent_labels.get("tenant_id")
    if not tenant_id:
        sys.exit(0)  # unlabelled agent — skip silently

    rule_level = int(alert.get("rule", {}).get("level", 0))
    if rule_level < 7:
        sys.exit(0)

    event = sanitise_event(alert, tenant_id)

    r = redis.Redis(
        host     = os.environ.get("REDIS_HOST", "localhost"),
        port     = int(os.environ.get("REDIS_PORT", 6379)),
        password = os.environ.get("REDIS_PASSWORD", "socredis"),
        decode_responses=True,
    )
    stream_key = f"soc:events:{tenant_id}"
    r.xadd(stream_key, {"payload": json.dumps(event)}, maxlen=10_000)


if __name__ == "__main__":
    main()
