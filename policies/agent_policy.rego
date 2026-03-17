package sao.agent.policy

# Default deny
default allow = false
default risk_level = "low"

# ── Allow rule ────────────────────────────────────────────────────────────────
allow {
    input.identity_type == "service"
    input.current_tenant_id != ""
    input.current_tenant_id == input.requested_tenant_id
    valid_tool_for_agent(input.tool_name, input.agent_id)
}

# ── Risk level ────────────────────────────────────────────────────────────────
risk_level = "high" {
    allow
    input.tool_name == "query_threat_intel"
    # Threat intel queries on external IOCs are higher risk — requires HITL review
    startswith(input.resource_id, "203.") # external IP space
}

risk_level = "low" {
    allow
    not risk_level == "high"
}

# ── Tool allowlists per agent ─────────────────────────────────────────────────
valid_tool_for_agent(tool, agent) {
    agent_tools := {
        "SOC-TRIAGE-001":      {"query_event_history", "query_asset_profile", "query_threat_intel"},
        "SOC-AUDITOR-001":     {"query_incident_data", "query_regulatory_templates"},
        "SOC-COMPLIANCE-001":  {"query_posture_data",  "query_framework_controls"},
        "SOC-REMEDIATION-001": {"query_incident_data", "query_playbook_templates"},
        "SOC-HUNTER-001":      {"query_asset_scores",  "query_cve_detail"},
    }
    tool == agent_tools[agent][_]
}

# ── Deny with reason (logged to Langfuse / audit log) ────────────────────────
deny[reason] {
    input.current_tenant_id != input.requested_tenant_id
    reason := sprintf(
        "cross_tenant_access: agent=%v requested_tenant=%v current_tenant=%v tool=%v",
        [input.agent_id, input.requested_tenant_id, input.current_tenant_id, input.tool_name]
    )
}

deny[reason] {
    input.current_tenant_id == ""
    reason := "missing_tenant_id: agent called tool without tenant_id"
}

deny[reason] {
    not valid_tool_for_agent(input.tool_name, input.agent_id)
    reason := sprintf(
        "tool_not_allowed: agent=%v tool=%v",
        [input.agent_id, input.tool_name]
    )
}
