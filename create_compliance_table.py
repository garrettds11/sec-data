#!/usr/bin/env python3
"""Generate illustrative CIS-inspired configuration assessments locally.

Synthetic, independently authored checks only; NOT an official CIS assessment.
Example: python create_compliance_table.py --dry-run --seed 42
         python create_compliance_table.py --region us-east-1 --append
"""
import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common.assets import build_hosts, iter_hosts, iso, DEFAULT_HOST_COUNT
from common.export import export_records, parse_times

DEFAULT_TABLE = "aiwebdemo-compliance-findings"
CATALOG_DIR = Path(__file__).resolve().parent / "catalogs" / "compliance"
DEFAULT_AS_OF = "2026-10-15T12:00:00Z"


def load_catalogs(directory=CATALOG_DIR):
    catalogs = []
    seen_keys = set()
    for path in sorted(Path(directory).glob("*.json")):
        catalog = json.loads(path.read_text(encoding="utf-8"))
        for key in ("benchmark_id", "benchmark_version", "benchmark_title", "os", "profile", "controls"):
            if key not in catalog:
                raise ValueError(f"{path.name}: missing {key}")
        ids = [c["id"] for c in catalog["controls"]]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{path.name}: duplicate control ID")
        for control in catalog["controls"]:
            finding_key = (catalog["benchmark_id"], catalog["benchmark_version"], control["id"])
            if finding_key in seen_keys:
                raise ValueError(f"{path.name}: duplicate control key across catalogs: {finding_key}")
            seen_keys.add(finding_key)
            for key in ("title", "category", "expected_value", "noncompliant_value",
                        "evidence_type", "evidence_source", "roles", "scenario"):
                if key not in control:
                    raise ValueError(f"{path.name}: {control['id']} missing {key}")
        catalogs.append(catalog)
    if not catalogs:
        raise ValueError("No compliance catalogs found")
    return catalogs


def stable_fraction(*parts):
    digest = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def assessment(host, control, seed):
    """Deterministic and coherent result: failed settings have corresponding actual values."""
    key = (host["short"], control["scenario"])
    planted = {
        ("dc-01", "password"): True,
        ("dc-01", "logging"): True,
        ("dc-02", "password"): False,
        ("bastion-01", "ssh"): True,
        ("prod-web-02", "ssh"): True,
        ("dev-app-01", "logging"): True,
        ("prod-file-01", "firewall"): True,
    }
    if key in planted:
        failed = planted[key]
    else:
        rate = {"prod": 0.15, "stage": 0.30, "dev": 0.47}[host["env"]]
        failed = stable_fraction(seed, host["short"], control["id"]) < rate
    return "fail" if failed else "pass", (
        control["noncompliant_value"] if failed else control["expected_value"]
    )


def iter_items(seed=42, as_of=DEFAULT_AS_OF, catalogs=None, host_count=DEFAULT_HOST_COUNT,
               findings_per_host=None):
    timestamp = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("--as-of must include a timezone")
    checked_at = iso(timestamp.astimezone(timezone.utc))
    catalogs = load_catalogs() if catalogs is None else catalogs
    if findings_per_host is not None and findings_per_host < 1:
        raise ValueError("--findings-per-host must be positive")
    for host in iter_hosts(random.Random(seed), host_count):
        host_items = []
        for catalog in catalogs:
            if host["os"] != catalog["os"]:  # exact product / release matching only
                continue
            for control in catalog["controls"]:
                if host["role"] not in control["roles"]:
                    continue
                status, actual = assessment(host, control, seed)
                key = f"{catalog['benchmark_id']}@{catalog['benchmark_version']}#{control['id']}"
                host_items.append({
                    "host_name": host["fqdn"], "finding_id": key,
                    "control_key": key, "control_id": control["id"],
                    "control_title": control["title"], "control_category": control["category"],
                    "benchmark_id": catalog["benchmark_id"],
                    "benchmark_version": catalog["benchmark_version"],
                    "benchmark_title": catalog["benchmark_title"],
                    "benchmark_profile": catalog["profile"],
                    "compliance_status": status,
                    "expected_value": control["expected_value"], "actual_value": actual,
                    "evidence_type": control["evidence_type"],
                    "evidence_source": control["evidence_source"],
                    "environment": host["env"], "host_ip": host["ip"], "host_mac": host["mac"],
                    "host_os_full": host["os"], "asset_role": host["role"],
                    "scanner_vendor": "Synthetic",
                    "scan_type": "authenticated" if host["authenticated"] else "unauthenticated",
                    "last_seen": checked_at, "synthetic": True,
                    "assessment_method": "simulated", "assessment_id": f"synthetic-{seed}-{checked_at}",
                })
        if findings_per_host is not None:
            if not host_items:  # Uncovered OS/role combinations are not assessed.
                continue
            if len(host_items) < findings_per_host:
                raise ValueError(f"{host['short']} has only {len(host_items)} applicable controls; requested {findings_per_host}")
            host_items = host_items[:findings_per_host]
        yield from host_items


def build_items(seed=42, as_of=DEFAULT_AS_OF, catalogs=None, host_count=DEFAULT_HOST_COUNT,
                findings_per_host=None):
    return list(iter_items(seed, as_of, catalogs, host_count, findings_per_host))


def summarize(items):
    counts = Counter(x["compliance_status"] for x in items)
    hosts = {x["host_name"] for x in items}
    print(f"Generated {len(items)} assessment findings on {len(hosts)} applicable hosts")
    print("Status:", dict(sorted(counts.items())))
    print("Planted checks:")
    for host, scenario in (("dc-01", "password"), ("bastion-01", "ssh"),
                           ("prod-web-02", "ssh"), ("prod-file-01", "firewall")):
        hits = [x for x in items if x["host_name"].startswith(host + ".")
                and x["compliance_status"] == "fail"
                and (("SSH" in x["control_category"] and scenario == "ssh")
                     or (scenario == "password" and "password" in x["control_title"].lower())
                     or (scenario == "firewall" and "firewall" in x["control_title"].lower()))]
        print(f"  {host} / {scenario}: {len(hits)} failing checks (if OS catalog applicable)")


def main():
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--as-of", default=DEFAULT_AS_OF)
    parser.add_argument("--snapshots", nargs="+", help="Ascending, unique ISO 8601 assessment times")
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT)
    parser.add_argument("--findings-per-host", type=int)
    parser.add_argument("--target-records", type=int)
    parser.add_argument("--format", choices=("json", "jsonl"), default="json")
    parser.add_argument("--catalog-dir", type=Path, default=CATALOG_DIR,
                        help="Directory of project-owned illustrative compliance catalog JSON files")
    parser.add_argument("--output", default="output/compliance-findings.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.snapshots and args.as_of != DEFAULT_AS_OF:
            raise ValueError("--as-of and --snapshots cannot be combined")
        times = parse_times(args.snapshots or [args.as_of])
        catalogs = load_catalogs(args.catalog_dir)
        catalog_roles = [(catalog["os"], {role for control in catalog["controls"]
                                          for role in control["roles"]}) for catalog in catalogs]
        applicable_hosts = sum(any(host["os"] == os_name and host["role"] in roles
                                   for os_name, roles in catalog_roles)
                               for host in iter_hosts(random.Random(args.seed), args.host_count))
        noncompliant = {(catalog["benchmark_id"], catalog["benchmark_version"], c["id"]):
                        c["noncompliant_value"] for catalog in catalogs
                        for c in catalog["controls"]}

        def records():
            for snapshot_index, as_of in enumerate(times):
                for item in iter_items(args.seed, as_of, catalogs=catalogs, host_count=args.host_count,
                                       findings_per_host=args.findings_per_host):
                    if len(times) > 1:
                        base_id = item["finding_id"]
                        item["base_finding_id"] = base_id
                        item["snapshot_id"] = as_of
                        item["finding_id"] = f"{base_id}@{as_of}"
                        if snapshot_index and stable_fraction(args.seed, item["host_name"], base_id) < 0.18:
                            item["compliance_status"] = "pass" if item["compliance_status"] == "fail" else "fail"
                            item["actual_value"] = (item["expected_value"] if item["compliance_status"] == "pass"
                                                    else noncompliant[(item["benchmark_id"], item["benchmark_version"],
                                                                       item["control_id"])])
                    yield item

        counts = Counter()
        sample = None
        def tally(item):
            nonlocal sample
            if sample is None:
                sample = item
            counts[item["compliance_status"]] += 1
        count = export_records(args.output, records(), args.format, args.target_records, tally, args.dry_run)
        if not count:
            raise ValueError("No applicable findings generated; check OS catalog coverage")
        print(f"Generated {count} assessment findings; inventory has {applicable_hosts} applicable hosts and "
              f"{args.host_count - applicable_hosts} hosts without an applicable OS/role catalog; "
              f"status: {dict(sorted(counts.items()))}")
        if args.dry_run:
            print("Sample item:", json.dumps(sample, sort_keys=True))
            print("Dry run; no file written")
        else:
            print(f"Wrote {count} findings to {Path(args.output).resolve()}")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
