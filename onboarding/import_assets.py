#!/usr/bin/env python3
"""
onboarding/import_assets.py — Import annotated asset database into PostgreSQL.

Run after:
  1. nmap_parser.py has produced asset_db.json
  2. Human annotation session completed (no REVIEW_REQUIRED values remaining)

Usage:
  python onboarding/import_assets.py \\
    --input /onboarding/tenant-pilot-id/asset_db.json \\
    --tenant-id tenant-pilot-id
"""

import argparse, asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from core.asset_registry import upsert_asset


def validate_asset(asset: dict, idx: int) -> list[str]:
    """Return list of validation errors for a single asset."""
    errors = []
    if asset.get("criticality") not in ("standard","important","critical"):
        errors.append(f"  Asset #{idx} {asset.get('asset_id')}: criticality must be standard|important|critical, got {asset.get('criticality')!r}")
    if asset.get("data_sensitivity") == "REVIEW_REQUIRED":
        errors.append(f"  Asset #{idx} {asset.get('asset_id')}: data_sensitivity not annotated")
    if asset.get("owner") == "REVIEW_REQUIRED":
        errors.append(f"  Asset #{idx} {asset.get('asset_id')}: owner not annotated")
    return errors


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",     required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--force",     action="store_true", help="Skip validation (not recommended)")
    args = parser.parse_args()

    assets = json.loads(Path(args.input).read_text())
    print(f"Loaded {len(assets)} assets from {args.input}")

    # Validate
    if not args.force:
        all_errors = []
        for i, asset in enumerate(assets, 1):
            all_errors.extend(validate_asset(asset, i))
        if all_errors:
            print("\nValidation failed — fix these before importing:")
            for e in all_errors:
                print(e)
            print(f"\nRe-run with --force to skip validation (not recommended for production).")
            sys.exit(1)

    # Strip internal-only fields before storing
    STRIP = {"_flags","_scan_source"}
    imported = 0
    for asset in assets:
        clean_profile = {k: v for k, v in asset.items() if k not in STRIP and k != "tenant_id"}
        await upsert_asset(args.tenant_id, asset["asset_id"], clean_profile)
        imported += 1
        print(f"  [{imported:3}] {asset['asset_id']:<20} criticality={asset.get('criticality'):<10} internet={asset.get('internet_facing')}")

    print(f"\n✓ Imported {imported} assets for tenant {args.tenant_id}")
    print(f"  Asset registry ready. Verify with:")
    print(f"  psql $POSTGRES_DSN -c \"SELECT asset_id, profile->>'criticality' FROM asset_registry WHERE tenant_id='{args.tenant_id}';\"")


if __name__ == "__main__":
    asyncio.run(main())
