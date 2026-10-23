#!/usr/bin/env python3
"""Export one reproducible synthetic environment and linked dataset bundle."""

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import create_compliance_table as compliance
import create_recon_events as recon
import create_vuln_table as vuln
from common.assets import DEFAULT_HOST_COUNT
from common.export import export_records, parse_times
from common.world import VERSION as WORLD_VERSION, SERVICES, iter_assets, iter_entities, iter_relationships, run_id
from common.zeek_dns import render_dns


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_recipe_text(path):
    content = Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def recipe_checksums():
    root = Path(__file__).resolve().parent
    paths = [root / name for name in (
        "create_story.py", "create_vuln_table.py", "create_compliance_table.py",
        "create_recon_events.py", "common/assets.py", "common/export.py", "common/world.py",
        "common/zeek_dns.py")]
    for catalog in ("compliance", "recon", "vulnerability"):
        paths.extend(sorted((root / "catalogs" / catalog).glob("*.json")))
    return {path.relative_to(root).as_posix(): sha256_recipe_text(path) for path in paths}


def validate_recon_truth(truth, seed, host_count):
    """Check references in the current recon manifest against exported world IDs."""
    assets = {a["asset_id"] for a in iter_assets(seed, min(host_count, DEFAULT_HOST_COUNT))}
    entities = {e["entity_id"] for e in iter_entities()}
    for operation in truth["operations"]:
        source = operation["source_ref"]
        if ("asset_id" in source) == ("entity_id" in source):
            raise ValueError("Operation must identify one source asset or entity")
        if source.get("asset_id") not in assets and source.get("entity_id") not in entities:
            raise ValueError("Operation source does not resolve in world catalog")
        event_ids = set(operation["event_ids"])
        if len(event_ids) != len(operation["event_ids"]):
            raise ValueError("Duplicate event ID in operation")
        if operation["last_observation_at"] < operation["start_time"]:
            raise ValueError("Observation predates operation")
        for link in operation["interaction_links"]:
            if link["event_id"] not in event_ids:
                raise ValueError("Interaction link references a missing event")
            for key in ("caused_by", "resolved_by", "retry_of"):
                if key in link and link[key] not in event_ids:
                    raise ValueError(f"Interaction link {key} does not resolve")
            if "target_asset_id" in link and link["target_asset_id"] not in assets:
                raise ValueError("Interaction target does not resolve")


def service_consistent_vulnerabilities(seed, as_of, host_count, skipped):
    """Keep only findings supported by this run's modeled service inventory."""
    assets = iter_assets(seed, host_count)
    asset = next(assets)
    for row in vuln.iter_items(seed, as_of, host_count):
        while asset["fqdn"] != row["host_name"]:
            asset = next(assets)
        if row["network_protocol"] == "local" and row["network_port"] == 0:
            row["asset_id"] = asset["asset_id"]
            yield row
        elif row["network_protocol"] == "tcp" and row["network_port"] in SERVICES[asset["role"]]:
            row["asset_id"] = asset["asset_id"]
            yield row
        else:
            skipped["unsupported_service"] += 1


def linked_compliance(seed, as_of, host_count):
    assets = iter_assets(seed, host_count)
    asset = next(assets)
    for row in compliance.iter_items(seed, as_of, host_count=host_count):
        while asset["fqdn"] != row["host_name"]:
            asset = next(assets)
        row["asset_id"] = asset["asset_id"]
        yield row


def export_story(seed, start, duration_minutes, campaign_count, host_count, output_dir):
    if start.tzinfo is None:
        raise ValueError("--start-time must include a timezone")
    if host_count < DEFAULT_HOST_COUNT:
        raise ValueError(f"Full story runs require at least {DEFAULT_HOST_COUNT} hosts")
    if not 1 <= campaign_count <= 100 or duration_minutes < 4 * campaign_count:
        raise ValueError("Invalid recon campaign count or duration")
    target = Path(output_dir).resolve()
    if target.exists():
        raise ValueError(f"Output directory already exists: {target}")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=parent))
    try:
        assessment_at = iso(start - timedelta(minutes=1))
        start_at = iso(start)
        recipe = recipe_checksums()
        recipe_hash = hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest()
        identity = run_id(seed, start_at, host_count, duration_minutes,
                          campaign_count, recipe_hash)
        files = {}

        def save(name, records):
            path = stage / name
            count = export_records(path, records, "jsonl")
            files[name] = {"records": count, "sha256": sha256_file(path)}
            return count

        save("assets.jsonl", iter_assets(seed, host_count))
        save("entities.jsonl", iter_entities())
        save("relationships.jsonl", iter_relationships(seed, host_count))
        skipped_findings = {"unsupported_service": 0}
        save("vulnerability.jsonl", service_consistent_vulnerabilities(
            seed, assessment_at, host_count, skipped_findings))
        save("compliance.jsonl", linked_compliance(seed, assessment_at, host_count))
        events, truth = recon.generate(seed, start, duration_minutes, campaign_count)
        save("recon.jsonl", events)
        validate_recon_truth(truth, seed, host_count)
        dns_events, _ = recon.generate(seed, start, duration_minutes, campaign_count)
        save("dns.log", (render_dns(e) for e in dns_events if e["event_type"] == "dns"))

        timeline = [{"kind": "baseline_assessment", "at": assessment_at,
                     "datasets": ["vulnerability.jsonl", "compliance.jsonl"]}]
        timeline.extend({"kind": "operation", "at": op["start_time"],
                         "operation_id": op["operation_id"], "family": op["family"],
                         "source_ref": op["source_ref"]} for op in truth["operations"])
        save("timeline.jsonl", iter(timeline))
        truth["run_id"] = identity
        truth_path = stage / "recon-truth.json"
        truth_path.write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8", newline="\n")
        files[truth_path.name] = {"sha256": sha256_file(truth_path)}
        manifest = {
            "schema_version": WORLD_VERSION, "run_id": identity,
            "seed": seed, "start_time": start_at, "assessment_time": assessment_at,
            "duration_minutes": duration_minutes, "campaign_count": campaign_count,
            "host_count": host_count,
            "generator_versions": {"world": WORLD_VERSION, "recon": recon.VERSION},
            "recipe_sha256": recipe_hash, "recipe_files": recipe,
            "filtered_vulnerability_findings": skipped_findings,
            "files": files,
            "notes": ["All source formats are synthetic", "Scenario truth is separate from observations",
                      "Recon activity currently uses the default 23 hosts"],
        }
        (stage / "run-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
        for attempt in range(5):
            try:
                os.replace(stage, target)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.1)
        return manifest
    finally:
        if stage.exists():
            if stage.resolve().parent != parent.resolve():
                raise RuntimeError("Refusing to clean up outside the output parent")
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--start-time", required=True, help="ISO 8601 timestamp with timezone")
    parser.add_argument("--duration-minutes", type=int, default=60)
    parser.add_argument("--campaign-count", type=int, default=1)
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT)
    parser.add_argument("--output-dir", required=True, help="New directory for this run")
    args = parser.parse_args()
    try:
        start = datetime.fromisoformat(parse_times([args.start_time])[0].replace("Z", "+00:00"))
        manifest = export_story(args.seed, start, args.duration_minutes,
                                args.campaign_count, args.host_count, args.output_dir)
        print(f"Wrote {manifest['run_id']} to {Path(args.output_dir).resolve()}")
        print("Records:", {name: item["records"] for name, item in manifest["files"].items()
                           if "records" in item})
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
