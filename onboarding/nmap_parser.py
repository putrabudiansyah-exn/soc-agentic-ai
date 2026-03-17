#!/usr/bin/env python3
"""
onboarding/nmap_parser.py — Parse nmap XML scan output into the asset registry.

This runs during client onboarding (Day 1, Step 3 of the onboarding runbook).
Produces a JSON asset database that is then imported to PostgreSQL and
annotated by the client network team.

Usage:
  python onboarding/nmap_parser.py \\
    --internal /onboarding/tenant-pilot-id/internal.xml \\
    --external /onboarding/tenant-pilot-id/external.xml \\
    --tenant-id tenant-pilot-id \\
    --output /onboarding/tenant-pilot-id/asset_db.json

  # Then review and annotate, then import:
  python onboarding/import_assets.py \\
    --input /onboarding/tenant-pilot-id/asset_db.json \\
    --tenant-id tenant-pilot-id
"""

import argparse, json, sys, xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


# Ports that are concerning when internet-facing
HIGH_RISK_INTERNET_PORTS = {
    22:   "SSH — ensure key-only auth, no password",
    23:   "Telnet — CRITICAL: unencrypted, should be disabled",
    3389: "RDP — high brute-force risk when internet-facing",
    5900: "VNC — CRITICAL: often unauthenticated",
    3306: "MySQL — database should never be internet-facing",
    5432: "PostgreSQL — database should never be internet-facing",
    1433: "MSSQL — database should never be internet-facing",
    27017:"MongoDB — database should never be internet-facing",
    6379: "Redis — CRITICAL: often unauthenticated if internet-facing",
    9200: "Elasticsearch — CRITICAL: often unauthenticated",
    2375: "Docker daemon — CRITICAL: gives root on host if exposed",
}

SENSITIVE_SERVICES = {
    "ldap", "kerberos", "radius", "ftp", "telnet", "vnc", "rdp", "nfs", "smb"
}


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse nmap XML output. Returns list of host dicts."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"
        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name", ip) if hostname_el is not None else ip
        os_el = host.find(".//osmatch")
        os_name = os_el.get("name","unknown") if os_el is not None else "unknown"
        ports = []
        for port_el in host.findall(".//port"):
            state_el  = port_el.find("state")
            service_el= port_el.find("service")
            if state_el is not None and state_el.get("state") == "open":
                portnum = int(port_el.get("portid", 0))
                svc     = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product","") if service_el is not None else ""
                version = service_el.get("version","") if service_el is not None else ""
                ports.append({
                    "port":    portnum,
                    "service": svc,
                    "product": product,
                    "version": version,
                    "banner":  f"{product} {version}".strip() or "",
                })
        hosts.append({"ip": ip, "hostname": hostname, "os": os_name, "open_ports": ports})
    return hosts


def derive_asset_profile(
    internal_host: Optional[dict],
    external_host:  Optional[dict],
    tenant_id:      str,
) -> dict:
    """
    Merge internal and external scan data into a structured asset profile.
    Flags that require human annotation are set to REVIEW_REQUIRED.
    """
    host     = internal_host or external_host
    ip       = host["ip"]
    hostname = host["hostname"]
    ports_i  = [p["port"] for p in (internal_host or {}).get("open_ports", [])]
    ports_e  = [p["port"] for p in (external_host  or {}).get("open_ports", [])]
    all_ports= list(set(ports_i + ports_e))

    internet_facing    = bool(external_host and external_host.get("open_ports"))
    firewall_protected = internet_facing and bool(
        set(ports_i) - set(ports_e)
    )   # ports visible internally but not externally → some firewall filtering

    services = list({
        p["service"]
        for p in (internal_host or {}).get("open_ports", [])
               + (external_host  or {}).get("open_ports", [])
        if p["service"]
    })

    # Risk flags
    flags = []
    if internet_facing:
        for port in ports_e:
            if port in HIGH_RISK_INTERNET_PORTS:
                flags.append(f"HIGH_RISK_PORT: {port} ({HIGH_RISK_INTERNET_PORTS[port]})")
    for svc in services:
        if svc.lower() in SENSITIVE_SERVICES:
            flags.append(f"SENSITIVE_SERVICE: {svc}")
    if internet_facing and not firewall_protected:
        flags.append("WARN: no firewall filtering detected between internet and internal")

    # Derive initial criticality hint (human must confirm)
    criticality_hint = "standard"
    for svc in services:
        if svc.lower() in {"ldap","kerberos","radius"}:
            criticality_hint = "critical"   # identity infrastructure
        elif svc.lower() in {"mysql","postgres","mssql","mongodb"}:
            criticality_hint = "important"  # data stores
    if internet_facing and criticality_hint == "standard":
        criticality_hint = "important"

    return {
        "asset_id":          hostname.lower().replace(" ","_"),
        "tenant_id":         tenant_id,
        "hostname":          hostname,
        "ip":                ip,
        "os":                host.get("os","unknown"),
        "open_ports":        all_ports,
        "services":          services,
        "internet_facing":   internet_facing,
        "firewall_protected":firewall_protected,

        # ── Fields requiring human annotation ────────────────────────────────
        "criticality":       criticality_hint,   # REVIEW: standard|important|critical
        "data_sensitivity":  "REVIEW_REQUIRED",  # low|medium|high|restricted
        "owner":             "REVIEW_REQUIRED",  # team responsible
        "ncii_sector_relevance": False,          # REVIEW: true if NCII asset
        "accepted_risks":    [],                 # document any formal risk acceptances

        "_flags":            flags,              # human attention items
        "_scan_source":      "nmap_onboarding",
    }


def merge_scans(
    internal_hosts: list[dict],
    external_hosts: list[dict],
    tenant_id: str,
) -> list[dict]:
    """Cross-reference internal and external scans to derive firewall context."""
    ext_by_ip = {h["ip"]: h for h in external_hosts}
    int_by_ip = {h["ip"]: h for h in internal_hosts}
    all_ips   = set(int_by_ip) | set(ext_by_ip)
    assets    = []
    for ip in all_ips:
        profile = derive_asset_profile(
            internal_host = int_by_ip.get(ip),
            external_host = ext_by_ip.get(ip),
            tenant_id     = tenant_id,
        )
        assets.append(profile)
    return sorted(assets, key=lambda a: a["ip"])


def print_summary(assets: list[dict]) -> None:
    flags_total = sum(len(a.get("_flags",[])) for a in assets)
    internet    = sum(1 for a in assets if a["internet_facing"])
    critical    = sum(1 for a in assets if a["criticality"] == "critical")
    print(f"\nOnboarding scan summary")
    print(f"{'═'*40}")
    print(f"  Total assets discovered: {len(assets)}")
    print(f"  Internet-facing:         {internet}")
    print(f"  Auto-classified critical:{critical}")
    print(f"  Flags requiring review:  {flags_total}")
    if flags_total:
        print(f"\n  Flags:")
        for a in assets:
            for flag in a.get("_flags",[]):
                print(f"    [{a['asset_id']}] {flag}")
    print(f"\n  NEXT: Review asset_db.json, annotate REVIEW_REQUIRED fields,")
    print(f"        then run: python onboarding/import_assets.py")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--internal",   required=True, help="Path to internal nmap XML")
    parser.add_argument("--external",   default="",    help="Path to external nmap XML (optional)")
    parser.add_argument("--tenant-id",  required=True)
    parser.add_argument("--output",     required=True, help="Output JSON path")
    args = parser.parse_args()

    print(f"Parsing internal scan: {args.internal}")
    internal_hosts = parse_nmap_xml(args.internal)
    print(f"  Found {len(internal_hosts)} live hosts")

    external_hosts = []
    if args.external:
        print(f"Parsing external scan: {args.external}")
        external_hosts = parse_nmap_xml(args.external)
        print(f"  Found {len(external_hosts)} externally visible hosts")

    assets = merge_scans(internal_hosts, external_hosts, args.tenant_id)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(assets, indent=2))
    print(f"\nWrote {len(assets)} assets → {args.output}")
    print_summary(assets)


if __name__ == "__main__":
    main()
