"""
pipeline/event_consumer.py — Redis XREADGROUP consumer.
Reads from per-tenant streams and submits to agent FastAPI endpoints.
At SAO migration: change TRIAGE_AGENT_URL to SAO backend API.
"""

import asyncio, json, os
import redis.asyncio as aioredis
import httpx
from dotenv import load_dotenv
load_dotenv()

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.logger import get_logger

logger     = get_logger(__name__)
GROUP_NAME = "triage-workers"
CONSUMER_ID= os.getenv("HOSTNAME", "consumer-local")
TENANT_IDS = [t.strip() for t in os.getenv("TENANT_IDS", "eval-tenant-id").split(",") if t.strip()]

# Lightweight: points to triage agent directly.
# SAO migration: change to http://sao-api.sao-platform:8000/jobs
TRIAGE_AGENT_URL = os.getenv("TRIAGE_AGENT_URL", "http://localhost:8080")


async def submit_to_triage(event: dict, tenant_id: str) -> str:
    """Submit event to Triage Agent. Returns job_id."""
    import uuid
    job_id = str(uuid.uuid4())

    async with httpx.AsyncClient(timeout=15.0) as c:
        resp = await c.post(f"{TRIAGE_AGENT_URL}/jobs", json={
            "job_id":       job_id,
            "agent_id":     "SOC-TRIAGE-001",
            "tenant_id":    tenant_id,
            "department_id":f"soc-{tenant_id}",
            "input":        event,
        })
        resp.raise_for_status()

    logger.info("job_submitted", extra={
        "job_id":   job_id,
        "event_id": event.get("event_id"),
        "tenant_id":tenant_id,
    })
    return job_id


async def consume():
    redis_url = os.getenv("REDIS_URL", "redis://:socredis@localhost:6379")
    r = await aioredis.from_url(redis_url, decode_responses=True)

    # Ensure consumer groups exist for all tenants
    for tenant_id in TENANT_IDS:
        stream = f"soc:events:{tenant_id}"
        try:
            await r.xgroup_create(stream, GROUP_NAME, id="0", mkstream=True)
        except Exception:
            pass  # group already exists

    logger.info("consumer_started", extra={"tenants": TENANT_IDS, "consumer": CONSUMER_ID})

    while True:
        streams = {f"soc:events:{t}": ">" for t in TENANT_IDS}
        try:
            results = await r.xreadgroup(
                GROUP_NAME, CONSUMER_ID,
                streams=streams,
                count=10,
                block=1000,
            )
        except Exception as e:
            logger.error("redis_read_error", extra={"error": str(e)})
            await asyncio.sleep(5)
            continue

        for stream_key, messages in (results or []):
            tenant_id = stream_key.split(":")[-1]
            for msg_id, fields in messages:
                try:
                    event = json.loads(fields["payload"])
                    await submit_to_triage(event, tenant_id)
                    await r.xack(stream_key, GROUP_NAME, msg_id)
                except Exception as e:
                    logger.error("event_processing_failed", extra={
                        "msg_id":    msg_id,
                        "tenant_id": tenant_id,
                        "error":     str(e),
                    })
                    # Do not ack — will retry on consumer restart


if __name__ == "__main__":
    asyncio.run(consume())
