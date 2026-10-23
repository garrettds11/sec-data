#!/usr/bin/env python3
"""Upload locally generated sec-data JSON findings to DynamoDB.

No AWS operations occur until the operator explicitly invokes this script.
"""
import argparse
import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from decimal import Decimal
from pathlib import Path

TABLES = {
    "vuln": {
        "default": "aiwebdemo-vuln-findings",
        "indexes": [("severity-lastseen-index", "vulnerability_severity", "last_seen"),
                    ("vuln-host-index", "vulnerability_id", "host_name")],
    },
    "compliance": {
        "default": "aiwebdemo-compliance-findings",
        "indexes": [("status-lastseen-index", "compliance_status", "last_seen"),
                    ("control-host-index", "control_key", "host_name")],
    },
}


def iter_items(path, dataset, history=False):
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        def source():
            with path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if line.strip():
                        try:
                            yield json.loads(line, parse_float=Decimal)
                        except json.JSONDecodeError as exc:
                            raise ValueError(f"Invalid JSONL line {line_number}: {exc}") from exc
    else:
        def source():
            with path.open(encoding="utf-8") as handle:
                items = json.load(handle, parse_float=Decimal)
            if not isinstance(items, list):
                raise ValueError("Input must be a JSON list or .jsonl file")
            yield from items
    required = {"host_name", "finding_id", "last_seen"}
    required.add("vulnerability_id" if dataset == "vuln" else "control_key")
    required.add("vulnerability_severity" if dataset == "vuln" else "compliance_status")
    for i, item in enumerate(source()):
        if not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not item[k] for k in required):
            raise ValueError(f"Item {i} missing required string fields: {sorted(required)}")
        if history and "snapshot_id" not in item:
            item = dict(item)
            item["snapshot_id"] = item.get("assessment_id", item["last_seen"])
            if not isinstance(item["snapshot_id"], str) or not item["snapshot_id"]:
                raise ValueError(f"Item {i} has invalid assessment_id for history mode")
            item["base_finding_id"] = item["finding_id"]
            item["finding_id"] += "@" + item["snapshot_id"]
        yield item


def load_items(path, dataset, history=False):
    items = list(iter_items(path, dataset, history))
    if not items:
        raise ValueError("Input must be non-empty")
    seen = set()
    for item in items:
        key = item["host_name"], item["finding_id"]
        if key in seen:
            raise ValueError(f"Duplicate primary key: {key}")
        seen.add(key)
    return items


def validate_input(path, dataset, history=False):
    """Preflight keys on disk, so JSONL uploads need no record-sized in-memory list."""
    with tempfile.TemporaryDirectory(dir=Path(path).resolve().parent) as temporary:
        with closing(sqlite3.connect(Path(temporary) / "keys.sqlite")) as database:
            database.execute("CREATE TABLE keys (host TEXT, finding TEXT, PRIMARY KEY (host, finding))")
            count = 0
            for item in iter_items(path, dataset, history):
                try:
                    database.execute("INSERT INTO keys VALUES (?, ?)",
                                     (item["host_name"], item["finding_id"]))
                except sqlite3.IntegrityError as exc:
                    raise ValueError(f"Duplicate primary key: {(item['host_name'], item['finding_id'])}") from exc
                count += 1
    if not count:
        raise ValueError("Input must be non-empty")
    return count


def choose_profile(boto3, specified):
    if specified:
        return specified
    profiles = boto3.session.Session().available_profiles
    if not sys.stdin.isatty():
        raise ValueError("Supply --profile for non-interactive operation")
    if not profiles:
        raise ValueError("No AWS shared-configuration profiles found. Run aws configure or aws configure sso.")
    print("Available AWS CLI profiles:")
    for i, name in enumerate(profiles, 1):
        print(f"  {i}. {name}")
    choice = input("Select profile number (or name): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(profiles):
        return profiles[int(choice) - 1]
    if choice in profiles:
        return choice
    raise ValueError("Invalid AWS profile selection")


def table_definition(name, dataset, tag):
    index_specs = TABLES[dataset]["indexes"]
    attributes = sorted({"host_name", "finding_id"} | {k for _, a, b in index_specs for k in (a, b)})
    return {
        "TableName": name,
        "BillingMode": "PAY_PER_REQUEST",
        "AttributeDefinitions": [{"AttributeName": a, "AttributeType": "S"} for a in attributes],
        "KeySchema": [
            {"AttributeName": "host_name", "KeyType": "HASH"},
            {"AttributeName": "finding_id", "KeyType": "RANGE"}
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": index,
                "KeySchema": [{"AttributeName": pk, "KeyType": "HASH"},
                              {"AttributeName": sk, "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"}
            } for index, pk, sk in index_specs
        ],
        "Tags": [{"Key": "project", "Value": tag}],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, choices=sorted(TABLES))
    parser.add_argument("--input", required=True, help="Locally generated JSON or JSONL file")
    parser.add_argument("--history", action="store_true", help="Append assessment time to single-snapshot finding IDs")
    parser.add_argument("--profile", help="AWS profile; prompts to choose when omitted")
    parser.add_argument("--region", help="Region, or use the chosen profile's default")
    parser.add_argument("--table", help="Override default DynamoDB table")
    parser.add_argument("--project-tag", default="aiwebdemo")
    parser.add_argument("--yes", action="store_true", help="Confirm uploads without prompting")
    args = parser.parse_args()
    try:
        count = validate_input(args.input, args.dataset, args.history)
        import boto3
        profile = choose_profile(boto3, args.profile)
        session = boto3.Session(profile_name=profile, region_name=args.region)
        if not session.region_name:
            raise ValueError("No region configured; supply --region")
        account = session.client("sts").get_caller_identity()["Account"]
        name = args.table or TABLES[args.dataset]["default"]
        print(f"Source: {args.input} ({count} records)")
        print(f"Destination: account={account}, region={session.region_name}, profile={profile}, table={name}")
        if not args.yes and input("Type UPLOAD to create/upsert findings: ").strip() != "UPLOAD":
            sys.exit("Aborted. No DynamoDB writes attempted.")
        client = session.client("dynamodb")
        try:
            client.describe_table(TableName=name)
            exists = True
        except client.exceptions.ResourceNotFoundException:
            exists = False
        if not exists:
            client.create_table(**table_definition(name, args.dataset, args.project_tag))
            client.get_waiter("table_exists").wait(TableName=name)
        else:
            table_info = client.describe_table(TableName=name)["Table"]
            keys = [(k["AttributeName"], k["KeyType"]) for k in table_info["KeySchema"]]
            if keys != [("host_name", "HASH"), ("finding_id", "RANGE")]:
                raise ValueError("Existing table has incompatible primary keys")
            expected_indexes = {x[0] for x in TABLES[args.dataset]["indexes"]}
            existing_indexes = {x["IndexName"] for x in table_info.get("GlobalSecondaryIndexes", [])}
            if not expected_indexes.issubset(existing_indexes):
                raise ValueError("Existing table lacks expected dataset indexes; no items uploaded")
        with session.resource("dynamodb").Table(name).batch_writer() as batch:
            for item in iter_items(args.input, args.dataset, args.history):
                batch.put_item(Item=item)
        print(f"Uploaded {count} {args.dataset} records to {name}")
    except (ValueError, OSError, json.JSONDecodeError, ImportError) as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
