# Triage Agent — SAO Migration Checklist

Run this checklist when migrating SOC-TRIAGE-001 from the lightweight stack to SAO Platform.
Estimated time: **2 hours** (mostly waiting for import pipeline).

## Pre-flight
- [ ] SAO platform smoke test passed (P0B.9)
- [ ] Migration readiness review completed (P0B.11)
- [ ] sao-agent-sdk installed and tested against SAO backend
- [ ] Both SAO admins briefed and available for HIGH risk quorum

## Step 1 — Swap 4 imports in graph.py

Open `agents/triage/graph.py`. Make exactly these changes:

```python
# BEFORE
from core.quality_signal import QualitySignal, Check, Severity
from core.cost_tracker   import write_token_cost_event
from core.logger         import get_logger

# AFTER
from sao_sdk.quality  import QualitySignal, Check, Severity
from sao_sdk.cost     import write_token_cost_event
from sao_sdk.logging  import get_logger
```

Remove the `await` in `write_token_cost_event` call if SAO SDK version is async:
```python
# Check SAO SDK docs — may need:
await write_token_cost_event({...})
```

## Step 2 — Add Langfuse trace handler to graph.py

In `build_triage_graph()`, add to compile call:
```python
# After imports, add:
from sao_sdk.tracing import get_trace_handler
```

In `agents/triage/main.py`, update config:
```python
config = {
    "configurable": {"thread_id": job_id},
    "callbacks":    [get_trace_handler(job_id=job_id, tenant_id=req.tenant_id)],
}
```

## Step 3 — Update main.py to accept SAO job_id

SAO backend provides `job_id` in the dispatch payload. Current code already accepts it
(`job_id: str = ""`). No change needed if SAO sends it in the same field.

Confirm SAO dispatch payload format with SAO Platform team.

## Step 4 — Update Dockerfile base image

```dockerfile
# BEFORE
FROM python:3.11-slim

# AFTER
FROM sao-base-images.ecr.ap-southeast-5.amazonaws.com/python:3.11-slim-v2.1.0
```

## Step 5 — Add requirements.txt entry

```
sao-agent-sdk>=1.0.0
```

## Step 6 — Write manifest.yaml

Create `agents/triage/manifest.yaml` using template from tech spec Section 6.2:

```yaml
apiVersion: sao/v1
kind: Agent
metadata:
  id: "SOC-TRIAGE-001"
  display_name: "AI SOC Triage Agent"
  version: "1.0.0"
  description: "Processes security events. Auto-resolves Tier 1. Escalates Tier 2/3."
  author: "soc-team@elitery.com"
  signed_by: customer
runtime:
  language: python
  version: "3.11"
  entrypoint: "agents.triage.main:app"
resources:
  cpu: "1000m"
  memory: "1Gi"
  gpu: false
sla:
  max_processing_time_seconds: 30
  p95_latency_target_ms: 25000
data_classification:
  contains_pii: true
  pii_types: ["ip_address", "hostname", "username"]
  sensitivity: "confidential"
  retention_days: 365
hitl:
  supported: true
  timeout_minutes: 30
  reviewer_role: "soc_analyst"
  decision_types:
    - id: APPROVE
      label: "Approve"
    - id: REJECT
      label: "Reject with reason"
    - id: ESCALATE
      label: "Escalate to senior analyst"
  correction_webhook: "/webhook/correction"
checks:
  - id: event_context_complete
    severity: HIGH
    name: "Event context assembled without error"
  - id: tier_determination_valid
    severity: HIGH
    name: "Tier classification produced valid output"
  - id: confidence_adequate
    severity: HIGH
    name: "Model confidence meets threshold"
  - id: lateral_movement_assessed
    severity: HIGH
    name: "Lateral movement field evaluated"
  - id: tenant_isolation_verified
    severity: HIGH
    name: "All tool calls within tenant scope"
  - id: tool_cap_respected
    severity: MEDIUM
    name: "Tool call count within limit"
  - id: token_budget_respected
    severity: LOW
    name: "Event within token budget"
```

## Step 7 — Package and submit to import pipeline

```bash
sao agent pack agents/triage/ --output SOC-TRIAGE-001-v1.0.0.saoagent
sao agent import SOC-TRIAGE-001-v1.0.0.saoagent
```

Risk classification is HIGH → 2-admin quorum required. Allow 48h.

## Step 8 — HITL cutover

1. Run lightweight HITL UI and SAO HITL dashboard in parallel for 1 week
2. Verify SAO dashboard shows HITL jobs correctly
3. CIRT-ID confirms workflow identical via SAO UI
4. Decommission: `docker compose stop hitl-ui`

## Step 9 — Verify

- [ ] Langfuse trace appears for a test job
- [ ] Quality Signal visible in SAO dashboard
- [ ] Token cost events in ClickHouse (via SAO SDK)
- [ ] HITL queue working in SAO UI (not lightweight HITL)
- [ ] Correction webhook still functional
- [ ] Run eval suite: `python eval/runner.py --jurisdiction ID` — accuracy unchanged

## What does NOT change

Everything in this list is byte-for-byte identical after migration:

- `agents/triage/tier_classifier.py` — deterministic rules
- `agents/triage/tools.py` — tool definitions and OPA dispatcher
- `agents/triage/graph.py` — all nodes, edges, graph structure (except 3 import lines)
- `core/opa_client.py` — same OPA address
- `core/context_builder.py` — same prompt assembly
- `core/tenant_registry.py` — same tenant config
- All 3 prompt files in `agents/triage/prompts/`
- `eval/` — all fixtures, runner, CI gate
- `policies/agent_policy.rego` — same OPA policy
- `pipeline/wazuh_to_queue.py` and `event_consumer.py` — unchanged
