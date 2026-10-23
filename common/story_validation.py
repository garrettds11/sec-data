"""Validate the cross-file contract of a linked synthetic story bundle."""

import argparse
import hashlib
import json
from itertools import zip_longest
from pathlib import Path

from common.zeek_dns import render_dns
from common.world import iter_assets, iter_entities, iter_relationships


def rows(path):
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def require(condition, message):
    if not condition:
        raise ValueError(f"Invalid story bundle: {message}")


def validate_bundle(path, truth):
    root = Path(path)
    seed = truth["seed"]
    asset_count = sum(1 for _ in rows(root / "assets.jsonl"))
    require(asset_count > 0, "empty asset catalog")
    assets = {}
    for expected, actual in zip_longest(iter_assets(seed, asset_count), rows(root / "assets.jsonl")):
        require(expected == actual, "asset catalog diverges from seeded inventory")
        if len(assets) < 23:
            assets[actual["asset_id"]] = actual
    entities = {row["entity_id"]: row for row in rows(root / "entities.jsonl")}
    require(list(entities.values()) == list(iter_entities()), "entity catalog diverges")
    for expected, actual in zip_longest(iter_relationships(seed, asset_count),
                                         rows(root / "relationships.jsonl")):
        require(expected == actual, "relationship catalog diverges")

    def valid_asset_id(value):
        return (isinstance(value, str) and value.startswith("asset-") and
                value[6:].isdigit() and 0 <= int(value[6:]) < asset_count)

    event_times = {}
    dns_count = 0
    for event in rows(root / "recon.jsonl"):
        eid = event["event_id"]
        require(eid not in event_times, "duplicate recon event ID")
        require(event["timestamp"] <= event["collected_at"], "collection predates event")
        event_times[eid] = event["timestamp"]
        if event["event_type"] == "dns":
            dns_count += 1
    for operation in truth["operations"]:
        source = operation["source_ref"]
        require(source.get("asset_id") in assets or source.get("entity_id") in entities,
                "operation source is missing")
        for eid in operation["event_ids"]:
            require(eid in event_times, "operation event is missing")
            require(operation["start_time"] <= event_times[eid] <= operation["last_observation_at"],
                    "event falls outside operation")
        for link in operation["interaction_links"]:
            eid = link["event_id"]
            require(eid in event_times, "interaction event is missing")
            require("target_asset_id" not in link or link["target_asset_id"] in assets,
                    "interaction target is missing")
            for field in ("caused_by", "resolved_by", "retry_of"):
                if field in link:
                    parent = link[field]
                    require(parent in event_times, "interaction parent is missing")
                    require(event_times[parent] <= event_times[eid],
                            "interaction parent occurs after child")
    require(set(event_times) == {eid for op in truth["operations"] for eid in op["event_ids"]},
            "unowned recon event")
    dns_source = (render_dns(event) for event in rows(root / "recon.jsonl")
                  if event["event_type"] == "dns")
    for expected, actual in zip_longest(dns_source, rows(root / "dns.log")):
        require(expected == actual, "Zeek DNS view diverges from normalized events")

    changes = list(rows(root / "state-changes.jsonl"))
    require(changes and len({c["change_id"] for c in changes}) == len(changes),
            "missing or duplicate state change")
    changes_by_kind = {}
    for change in changes:
        require(valid_asset_id(change["asset_id"]), "state change asset is missing")
        require(all(op["last_observation_at"] < change["effective_at"]
                    for op in truth["operations"]), "state change predates recon")
        key = (change["asset_id"], change["finding_id"])
        kind_changes = changes_by_kind.setdefault(change["finding_type"], {})
        require(key not in kind_changes, "duplicate finding state change")
        kind_changes[key] = change
    for kind in ("vulnerability", "compliance"):
        require(kind in changes_by_kind, f"missing {kind} state change")
        applied = set()
        asset_stream = iter_assets(seed, asset_count)
        asset = next(asset_stream)
        before = rows(root / f"{kind}.jsonl")
        after = rows(root / f"{kind}-followup.jsonl")
        for old, new in zip_longest(before, after):
            require(old is not None and new is not None, "follow-up row count differs")
            key = (old["asset_id"], old["finding_id"])
            require(key == (new["asset_id"], new["finding_id"]),
                    "follow-up finding identity differs")
            while asset["asset_id"] < key[0]:
                asset = next(asset_stream, None)
                require(asset is not None, "finding asset is missing")
            require(asset["asset_id"] == key[0], "finding asset is missing or out of order")
            require(old["host_ip"] == asset["ip"] == new["host_ip"],
                    "finding host address differs")
            change = changes_by_kind[kind].get(key)
            if change:
                require(old[f"{kind}_status"] == change["before"] and
                        new[f"{kind}_status"] == change["after"],
                        "state change does not match assessments")
                require(new["remediation_change_id"] == change["change_id"],
                        "follow-up does not reference its change")
                require(new["assessment_at"] > change["effective_at"],
                        "follow-up assessment predates change")
                if kind == "compliance":
                    require(old["actual_value"] == change["actual_value_before"] and
                            new["actual_value"] == change["actual_value_after"],
                            "control value does not match change")
                applied.add(key)
            else:
                require(old[f"{kind}_status"] == new[f"{kind}_status"],
                        "unplanned finding status change")
        require(applied == set(changes_by_kind[kind]), "state change finding is missing")
    timeline = list(rows(root / "timeline.jsonl"))
    require([item["at"] for item in timeline] == sorted(item["at"] for item in timeline),
            "timeline is out of order")
    require({item["change_id"] for item in timeline if item["kind"] == "state_change"} ==
            {change["change_id"] for change in changes}, "timeline change set differs")
    return {"assets": asset_count, "recon_events": len(event_times),
            "dns_events": dns_count, "state_changes": len(changes)}


def validate_export(path):
    root = Path(path)
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    truth = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
    require(truth["run_id"] == manifest["run_id"], "run IDs differ")
    for name, info in manifest["files"].items():
        digest = hashlib.sha256()
        with (root / name).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        require(digest.hexdigest() == info["sha256"], f"checksum differs: {name}")
    result = validate_bundle(root, truth)
    require(result == manifest["validation"], "validation summary differs")
    return result


def main():
    parser = argparse.ArgumentParser(description="Validate a linked synthetic story export")
    parser.add_argument("path", help="Directory containing run-manifest.json")
    args = parser.parse_args()
    try:
        print(json.dumps(validate_export(args.path), sort_keys=True))
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
