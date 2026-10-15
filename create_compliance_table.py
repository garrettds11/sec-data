#!/usr/bin/env python3
"""Generate illustrative CIS-inspired configuration assessment data in DynamoDB.

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

from common.assets import build_hosts, iso

DEFAULT_TABLE = "aiwebdemo-compliance-findings"
CATALOG_DIR = Path(__file__).resolve().parent / "catalogs" / "compliance"
DEFAULT_AS_OF = "2026-10-15T12:00:00Z"


def load_catalogs(directory=CATALOG_DIR):
    catalogs = []
    for path in sorted(Path(directory).glob("*.json")):
        catalog = json.loads(path.read_text(encoding="utf-8"))
        for key in ("benchmark_id", "benchmark_version", "os", "profile", "controls"):
            if key not in catalog:
                raise ValueError(f"{path.name}: missing {key}")
        ids = [c["id"] for c in catalog["controls"]]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{path.name}: duplicate control ID")
        for control in catalog["controls"]:
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


def build_items(seed=42, as_of=DEFAULT_AS_OF, catalogs=None):
    timestamp = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("--as-of must include a timezone")
    checked_at = iso(timestamp.astimezone(timezone.utc))
    hosts = build_hosts(random.Random(seed))  # identical host generation to vulnerability generator
    catalogs = load_catalogs() if catalogs is None else catalogs
    items = []
    for host in hosts:
        for catalog in catalogs:
            if host["os"] != catalog["os"]:  # exact product / release matching only
                continue
            for control in catalog["controls"]:
                if host["role"] not in control["roles"]:
                    continue
                status, actual = assessment(host, control, seed)
                key = f"{catalog['benchmark_id']}@{catalog['benchmark_version']}#{control['id']}"
                items.append({
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
    return items


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default=DEFAULT_TABLE)
    parser.add_argument("--region")
    parser.add_argument("--profile")
    parser.add_argument("--project-tag", default="aiwebdemo")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--as-of", default=DEFAULT_AS_OF, help="ISO-8601 UTC timestamp")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--append", action="store_true", help="Upsert current assessments")
    parser.add_argument("--delete", action="store_true")
    args = parser.parse_args()
    if args.delete and args.dry_run:
        parser.error("--delete and --dry-run are mutually exclusive")
    items = build_items(args.seed, args.as_of)
    if args.dry_run:
        summarize(items)
        if items:
            print(json.dumps(items[0], indent=2, sort_keys=True))
        return
    if not items and not args.delete:
        sys.exit("No applicable findings generated; refusing to create an empty table.")
    try:
        import boto3
    except ImportError:
        sys.exit("Install boto3 for DynamoDB access: pip install boto3")
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if not session.region_name:
        sys.exit("Pass --region or configure an AWS default region.")
    client = session.client("dynamodb")
    table = session.resource("dynamodb").Table(args.table)
    try:
        client.describe_table(TableName=args.table)
        exists = True
    except client.exceptions.ResourceNotFoundException:
        exists = False
    if args.delete:
        if not exists:
            sys.exit(f"Table {args.table} does not exist.")
        if input(f"Type '{args.table}' to confirm deletion: ").strip() != args.table:
            sys.exit("Aborted.")
        client.delete_table(TableName=args.table)
        client.get_waiter("table_not_exists").wait(TableName=args.table)
        print("Deleted.")
        return
    if exists and not args.append:
        sys.exit(f"Table {args.table} already exists; pass --append to upsert.")
    if not exists:
        client.create_table(
            TableName=args.table, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": k, "AttributeType": "S"} for k in (
                    "host_name", "finding_id", "compliance_status", "last_seen", "control_key"
                )
            ],
            KeySchema=[
                {"AttributeName": "host_name", "KeyType": "HASH"},
                {"AttributeName": "finding_id", "KeyType": "RANGE"}
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "status-lastseen-index",
                    "KeySchema": [
                        {"AttributeName": "compliance_status", "KeyType": "HASH"},
                        {"AttributeName": "last_seen", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                },
                {
                    "IndexName": "control-host-index",
                    "KeySchema": [
                        {"AttributeName": "control_key", "KeyType": "HASH"},
                        {"AttributeName": "host_name", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            Tags=[{"Key": "project", "Value": args.project_tag}]
        )
        client.get_waiter("table_exists").wait(TableName=args.table)
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)
    summarize(items)
    print(f"Upserted {len(items)} current findings into {args.table}")


if __name__ == "__main__":
    main()
