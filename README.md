# AI SOC Pod — Lightweight Stack

All five agents built on thin Python shims. No SAO dependency.
Go live faster. Migrate to SAO when it's ready.

## Quick start (5 minutes)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env: add VLLM_API_KEY (Together.ai key)

# 2. Start all services
docker compose up -d

# 3. Initialise databases
python scripts/init_db.py

# 4. Verify Triage Agent is alive
curl http://localhost:8080/health

# 5. Run a test event
python scripts/run_event.py --mock-event brute-force-critical

# 6. View HITL dashboard
open http://localhost:8090
```

## Run the eval suite

```bash
# Generate 60 fixtures for Indonesia (takes ~1 min)
python eval/generate_fixtures.py --jurisdiction ID --count 60

# Run eval (needs Triage Agent running)
python eval/runner.py --jurisdiction ID

# If accuracy < 92%, analyse failures
python eval/analyse_failures.py --results eval/baselines/ID_latest.json
```

## Project structure

```
soc-pod/
├── core/                    # Shared modules (ALL unchanged at SAO migration)
│   ├── quality_signal.py    # ← SHIM: swap to sao_sdk.quality at migration
│   ├── cost_tracker.py      # ← SHIM: swap to sao_sdk.cost at migration
│   ├── hitl_client.py       # ← SHIM: remove at migration
│   ├── logger.py            # ← SHIM: swap to sao_sdk.logging at migration
│   ├── tenant_registry.py   # Unchanged
│   ├── opa_client.py        # Unchanged
│   ├── llm_client.py        # Unchanged
│   ├── context_builder.py   # Unchanged
│   ├── asset_registry.py    # Unchanged
│   ├── siem_adapter.py      # Unchanged
│   └── siem_mock.py         # Unchanged (15 fixture events)
│
├── agents/triage/           # Triage Agent (first agent to build)
│   ├── tier_classifier.py   # Deterministic rules — NEVER in LLM
│   ├── tools.py             # Tool definitions + OPA dispatcher
│   ├── graph.py             # LangGraph StateGraph (all nodes)
│   ├── main.py              # FastAPI entrypoint
│   ├── Dockerfile
│   ├── migration_checklist.md  # Exact steps for SAO migration
│   └── prompts/
│       ├── ID_triage.txt    # Indonesia (BSSN/PDP/OJK) — build this first
│       └── MY_triage.txt    # Malaysia (CSA 2024/NACSA/PDPA) — parallel
│
├── hitl_ui/                 # Lightweight HITL review UI (decommissioned at migration)
│   ├── main.py              # FastAPI + Jinja2 review interface
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── review.html
│   └── Dockerfile
│
├── pipeline/                # Event ingestion (unchanged at migration)
│   ├── wazuh_to_queue.py    # Wazuh → Redis Streams
│   ├── event_consumer.py    # Redis → Triage Agent
│   └── Dockerfile
│
├── policies/
│   └── agent_policy.rego    # OPA policy (unchanged at migration)
│
├── eval/
│   ├── generate_fixtures.py # Auto-generate from Wazuh rule library
│   ├── runner.py            # Submit fixtures, measure accuracy
│   ├── analyse_failures.py  # Failure analysis for prompt iteration
│   ├── fixtures/ID/         # 50+ labeled ID events (build this first)
│   └── fixtures/MY/         # 50+ labeled MY events (parallel)
│
├── scripts/
│   ├── init_db.py           # Create all DB tables + seed eval assets
│   └── run_event.py         # Run a single event for debugging
│
├── docker-compose.yml       # Full dev stack (one command)
├── requirements.txt         # All deps pinned
└── .env.example             # All env vars with migration notes
```

## What changes at SAO migration

4 import swaps + 1 new file per agent. Everything else is identical.

| File | Before | After |
|---|---|---|
| `core/quality_signal.py` | writes to PostgreSQL | swap to `sao_sdk.quality` |
| `core/cost_tracker.py` | writes to ClickHouse | swap to `sao_sdk.cost` |
| `core/hitl_client.py` | POSTs to HITL UI | remove — SAO reads QS.passed |
| `core/logger.py` | JSON to stdout | swap to `sao_sdk.logging` |
| (none) | no manifest.yaml | add `manifest.yaml` per agent |

See `agents/triage/migration_checklist.md` for the full step-by-step.

## Jurisdiction prompt build order

1. `ID_triage.txt` — build first (Indonesia is first go-live)
2. Iterate with eval until ID accuracy >= 92%
3. `MY_triage.txt` — fork from ID, replace REGULATORY CONTEXT section
4. `DE_triage.txt` — German language, BSI/NIS2/DSGVO (Phase 9)

## Service ports (local dev)

| Service | Port | URL |
|---|---|---|
| Triage Agent | 8080 | http://localhost:8080 |
| HITL UI | 8090 | http://localhost:8090 |
| PostgreSQL | 5432 | psql -h localhost -U soc socdev |
| Redis | 6379 | redis-cli -a socredis |
| ClickHouse | 8123 | http://localhost:8123 |
| OPA | 8181 | http://localhost:8181 |
