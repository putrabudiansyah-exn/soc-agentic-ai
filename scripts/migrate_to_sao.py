#!/usr/bin/env python3
"""
scripts/migrate_to_sao.py — Automated Phase 8 SAO migration assistant.

Checks prerequisites, performs safe import swaps, generates manifest.yaml files,
and validates the migration. Run in dry-run mode first.

Usage:
  # Dry run — shows what would change, touches nothing:
  python scripts/migrate_to_sao.py --dry-run

  # Migrate one agent at a time:
  python scripts/migrate_to_sao.py --agent triage
  python scripts/migrate_to_sao.py --agent auditor
  ...

  # Validate a migrated agent (after swap, before sao agent pack):
  python scripts/migrate_to_sao.py --validate triage
"""

import argparse, os, re, shutil, sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

AGENTS = ["triage", "auditor", "compliance", "remediation", "threat_hunter"]

# The 4 shim swaps per agent — (old_import, new_import)
SHIM_SWAPS = [
    (
        "from core.quality_signal import QualitySignal, Check, Severity",
        "from sao_sdk.quality     import QualitySignal, Check, Severity",
    ),
    (
        "from core.cost_tracker   import write_token_cost_event",
        "from sao_sdk.cost        import write_token_cost_event",
    ),
    (
        "from core.cost_tracker import write_token_cost_event",
        "from sao_sdk.cost     import write_token_cost_event",
    ),
    (
        "from core.logger         import get_logger",
        "from sao_sdk.logging     import get_logger",
    ),
    (
        "from core.logger import get_logger",
        "from sao_sdk.logging import get_logger",
    ),
]

# hitl_client is removed entirely at migration
HITL_IMPORT_PATTERN = re.compile(r"^from core\.hitl_client import.*$", re.MULTILINE)

DOCKERFILE_SWAP = (
    "FROM python:3.11-slim",
    "FROM sao-base-images.ecr.ap-southeast-5.amazonaws.com/python:3.11-slim-v2.1.0",
)

REQUIREMENTS_ADD = "sao-agent-sdk>=1.0.0\n"


# ── Prerequisite checks ───────────────────────────────────────────────────────

def check_prerequisites() -> list[str]:
    issues = []
    # SAO SDK installed?
    try:
        import sao_sdk
    except ImportError:
        issues.append("sao-agent-sdk not installed — run: pip install sao-agent-sdk>=1.0.0")

    # sao CLI available?
    if shutil.which("sao") is None:
        issues.append("SAO CLI not found in PATH — install from SAO Platform team")

    # Migration readiness marker
    readiness_file = ROOT / ".sao_migration_ready"
    if not readiness_file.exists():
        issues.append(
            "SAO platform readiness not confirmed. "
            "After P0B.11 (migration readiness review), create: touch .sao_migration_ready"
        )
    return issues


# ── Per-file swap ─────────────────────────────────────────────────────────────

def swap_file(path: Path, dry_run: bool) -> list[str]:
    """Apply all shim swaps to a Python file. Returns list of changes made."""
    if not path.exists():
        return []
    original = path.read_text()
    content  = original
    changes  = []

    for old, new in SHIM_SWAPS:
        if old in content:
            content = content.replace(old, new)
            changes.append(f"  {path.relative_to(ROOT)}: swapped {old.split()[1]} → {new.split()[1]}")

    # Remove hitl_client import and call
    hitl_matches = HITL_IMPORT_PATTERN.findall(content)
    if hitl_matches:
        content = HITL_IMPORT_PATTERN.sub(
            "# MIGRATED: hitl_client removed — SAO reads QS.passed for HITL routing",
            content,
        )
        changes.append(f"  {path.relative_to(ROOT)}: removed hitl_client import (SAO handles HITL routing)")

    if content != original and not dry_run:
        # Backup original
        backup = path.with_suffix(path.suffix + ".pre_migration")
        shutil.copy(path, backup)
        path.write_text(content)

    return changes


def swap_dockerfile(path: Path, dry_run: bool) -> list[str]:
    if not path.exists(): return []
    content = path.read_text()
    old, new = DOCKERFILE_SWAP
    if old not in content: return []
    if not dry_run:
        backup = path.with_suffix(".pre_migration")
        shutil.copy(path, backup)
        path.write_text(content.replace(old, new))
    return [f"  {path.relative_to(ROOT)}: updated base image to SAO ECR image"]


def update_requirements(dry_run: bool) -> list[str]:
    req_path = ROOT / "requirements.txt"
    content  = req_path.read_text()
    if "sao-agent-sdk" in content:
        return ["  requirements.txt: sao-agent-sdk already present"]
    if not dry_run:
        req_path.write_text(content + REQUIREMENTS_ADD)
    return ["  requirements.txt: added sao-agent-sdk>=1.0.0"]


def generate_manifest(agent: str, dry_run: bool) -> list[str]:
    """Generate manifest.yaml from migration_checklist template."""
    checklist = ROOT / "agents" / agent / "migration_checklist.md"
    manifest  = ROOT / "agents" / agent / "manifest.yaml"
    if manifest.exists():
        return [f"  agents/{agent}/manifest.yaml: already exists — skipping"]
    if not checklist.exists():
        return [f"  agents/{agent}/manifest.yaml: no migration_checklist.md found — write manually"]

    # Extract manifest YAML block from migration_checklist.md
    text   = checklist.read_text()
    start  = text.find("```yaml\napiVersion: sao/v1")
    end    = text.find("\n```", start)
    if start == -1 or end == -1:
        return [f"  agents/{agent}/manifest.yaml: no YAML block in checklist — write manually"]

    yaml_content = text[start+7:end]
    if not dry_run:
        manifest.write_text(yaml_content)
    return [f"  agents/{agent}/manifest.yaml: generated from migration_checklist.md"]


# ── Validation ────────────────────────────────────────────────────────────────

def validate_agent(agent: str) -> list[str]:
    """Check migration is complete for an agent."""
    issues = []
    agent_dir = ROOT / "agents" / agent

    for py_file in agent_dir.rglob("*.py"):
        content = py_file.read_text()
        if "from core.quality_signal" in content:
            issues.append(f"FAIL: {py_file.relative_to(ROOT)} still imports from core.quality_signal")
        if "from core.cost_tracker" in content:
            issues.append(f"FAIL: {py_file.relative_to(ROOT)} still imports from core.cost_tracker")
        if "from core.logger" in content:
            issues.append(f"FAIL: {py_file.relative_to(ROOT)} still imports from core.logger")
        if "from core.hitl_client" in content:
            issues.append(f"FAIL: {py_file.relative_to(ROOT)} still imports from core.hitl_client")

    manifest_path = agent_dir / "manifest.yaml"
    if not manifest_path.exists():
        issues.append(f"FAIL: agents/{agent}/manifest.yaml missing — run generate_manifest first")
    else:
        manifest = manifest_path.read_text()
        for required in ["apiVersion: sao/v1", "kind: Agent", "entrypoint:", "checks:"]:
            if required not in manifest:
                issues.append(f"FAIL: manifest.yaml missing required field: {required}")

    dockerfile = agent_dir / "Dockerfile"
    if dockerfile.exists():
        if "python:3.11-slim" in dockerfile.read_text() and \
           "sao-base-images" not in dockerfile.read_text():
            issues.append(f"WARN: {agent}/Dockerfile still uses python:3.11-slim base image")

    return issues


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--agent",    choices=AGENTS, help="Migrate a specific agent")
    g.add_argument("--all",      action="store_true", help="Migrate all agents")
    g.add_argument("--validate", choices=AGENTS, help="Validate a migrated agent")
    g.add_argument("--check",    action="store_true", help="Check prerequisites only")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    args = parser.parse_args()

    # Prerequisite check
    if args.check:
        issues = check_prerequisites()
        if issues:
            print("Prerequisites not met:")
            for i in issues: print(f"  {i}")
        else:
            print("All prerequisites met. Safe to proceed.")
        return

    # Validate
    if args.validate:
        issues = validate_agent(args.validate)
        if issues:
            print(f"Validation FAILED for {args.validate}:")
            for i in issues: print(f"  {i}")
            sys.exit(1)
        else:
            print(f"✓ {args.validate} agent: migration validated. Safe to: sao agent pack agents/{args.validate}/")
        return

    # Migration
    agents_to_migrate = AGENTS if args.all else [args.agent]
    mode = "DRY RUN" if args.dry_run else "MIGRATING"
    print(f"{mode}: {', '.join(agents_to_migrate)}\n")

    if not args.dry_run:
        issues = check_prerequisites()
        if issues:
            print("Prerequisites not met — run with --check for details")
            for i in issues: print(f"  {i}")
            sys.exit(1)

    all_changes = []

    # requirements.txt
    all_changes.extend(update_requirements(args.dry_run))

    for agent in agents_to_migrate:
        print(f"\n── {agent} ──")
        agent_dir = ROOT / "agents" / agent
        for py_file in sorted(agent_dir.rglob("*.py")):
            changes = swap_file(py_file, args.dry_run)
            all_changes.extend(changes)
            for c in changes: print(c)

        dockerfile_changes = swap_dockerfile(agent_dir / "Dockerfile", args.dry_run)
        all_changes.extend(dockerfile_changes)
        for c in dockerfile_changes: print(c)

        manifest_changes = generate_manifest(agent, args.dry_run)
        all_changes.extend(manifest_changes)
        for c in manifest_changes: print(c)

    print(f"\n{'─'*60}")
    print(f"{'DRY RUN complete' if args.dry_run else 'Migration complete'}: {len(all_changes)} changes")

    if not args.dry_run:
        print("\nNext steps:")
        for agent in agents_to_migrate:
            print(f"  python scripts/migrate_to_sao.py --validate {agent}")
            print(f"  sao agent pack agents/{agent}/ --output SOC-{agent.upper()}-001-v1.0.0.saoagent")
            print(f"  sao agent import SOC-{agent.upper()}-001-v1.0.0.saoagent")
    else:
        print("\nNo files changed. Re-run without --dry-run to apply.")


if __name__ == "__main__":
    main()
