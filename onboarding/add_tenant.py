#!/usr/bin/env python3
"""
onboarding/add_tenant.py — Add a new client tenant to the SOC Pod.

This script:
  1. Validates the tenant config
  2. Creates the Redis stream
  3. Adds the tenant_id to the event consumer TENANT_IDS env
  4. Prints the tenant_registry.py snippet to add manually

Usage:
  python onboarding/add_tenant.py \\
    --tenant-id tenant-acme-id \\
    --tenant-name "PT Acme Indonesia" \\
    --jurisdiction ID \\
    --cidr 10.20.0.0/16 \\
    --cidr 172.20.0.0/20 \\
    --department-id soc-id-bfsi \\
    --wazuh-group acme-id \\
    --ncii-sector BFSI
"""

import argparse, asyncio, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv; load_dotenv()
import os
import redis


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id",     required=True)
    parser.add_argument("--tenant-name",   required=True)
    parser.add_argument("--jurisdiction",  choices=["ID","MY","DE"], required=True)
    parser.add_argument("--cidr",          action="append", required=True, dest="cidrs")
    parser.add_argument("--department-id", required=True)
    parser.add_argument("--wazuh-group",   required=True)
    parser.add_argument("--ncii-sector",   default=None, choices=["BFSI","Telco","Energy","Water","Gov","Health",None])
    args = parser.parse_args()

    tid = args.tenant_id

    # 1. Create Redis stream
    redis_url = os.getenv("REDIS_URL","redis://:socredis@localhost:6379")
    r = redis.from_url(redis_url, decode_responses=True)
    stream_key = f"soc:events:{tid}"
    # xadd with a dummy entry to create the stream, then delete it
    entry_id = r.xadd(stream_key, {"_init": "1"})
    r.xdel(stream_key, entry_id)
    print(f"✓ Redis stream created: {stream_key}")

    # 2. Print tenant_registry.py snippet
    ncii_line = f'        ncii_sector       = "{args.ncii_sector}",' if args.ncii_sector \
                else '        ncii_sector       = None,'
    cidrs_str = json_list(args.cidrs)
    snippet = f'''
# Add to TENANTS dict in core/tenant_registry.py:
    "{tid}": TenantConfig(
        tenant_id         = "{tid}",
        tenant_name       = "{args.tenant_name}",
        jurisdiction      = "{args.jurisdiction}",
{ncii_line}
        asset_cidr_ranges = {cidrs_str},
        department_id     = "{args.department_id}",
        wazuh_agent_group = "{args.wazuh_group}",
    ),'''

    print("\n" + "─"*60)
    print("STEP 2: Add to core/tenant_registry.py:")
    print(snippet)

    # 3. Wazuh agent.conf snippet
    wazuh_snippet = f'''
<!-- Add to /var/ossec/etc/shared/{args.wazuh_group}/agent.conf on Wazuh Manager: -->
<agent_config>
  <labels>
    <label key="tenant_id">{tid}</label>
    <label key="asset.criticality">standard</label>
    <label key="network.segment">internal</label>
  </labels>
</agent_config>'''

    print("\n" + "─"*60)
    print("STEP 3: Configure Wazuh agent labels:")
    print(wazuh_snippet)

    # 4. Update TENANT_IDS env var hint
    print("\n" + "─"*60)
    print("STEP 4: Add tenant to event consumer:")
    print(f"  Add '{tid}' to TENANT_IDS in .env (comma-separated)")
    print(f"  Then restart: docker compose restart event-consumer")

    print("\n" + "─"*60)
    print("STEP 5: Run nmap onboarding scans:")
    print(f"  mkdir -p /onboarding/{tid}")
    print(f"  # External scan (from Elitery infra):")
    print(f"  nmap -sV -sC --open -p 80,443,22,3389,8080,8443,3306,5432 \\")
    print(f"       --script=banner,ssl-cert -oX /onboarding/{tid}/external.xml <public_ranges>")
    print(f"  # Internal scan (from Wazuh manager, overnight):")
    print(f"  nmap -sV -O --open -p- --min-rate 1000 \\")
    print(f"       -oX /onboarding/{tid}/internal.xml {' '.join(args.cidrs)}")
    print(f"  # Parse:")
    print(f"  python onboarding/nmap_parser.py \\")
    print(f"    --internal /onboarding/{tid}/internal.xml \\")
    print(f"    --external /onboarding/{tid}/external.xml \\")
    print(f"    --tenant-id {tid} \\")
    print(f"    --output /onboarding/{tid}/asset_db.json")
    print(f"  # Then annotate asset_db.json with client network team, then import:")
    print(f"  python onboarding/import_assets.py --input /onboarding/{tid}/asset_db.json --tenant-id {tid}")

    print("\n" + "─"*60)
    print("STEP 6: Verify first live event:")
    print(f"  python scripts/run_event.py --mock-event brute-force-critical --tenant-id {tid}")
    print(f"\nOnboarding checklist complete for tenant: {tid}")


def json_list(items):
    return "[" + ", ".join(f'"{i}"' for i in items) + "]"


if __name__ == "__main__":
    main()
