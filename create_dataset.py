#!/usr/bin/env python3
"""Publish one linked run with CIM-shaped analyst events and separate context."""

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from common.assets import DEFAULT_HOST_COUNT
from common.background import (VERSION as BACKGROUND_VERSION, DEFAULT_MIX,
                               iter_events as background_events)
from common.cim import CIM_VERSION, SOURCES
from common.event_streams import publish_events
from common.export import export_records, parse_times
from common.identity import iter_identities
from common.scenario import compile_scenario, load_scenario, merge_scenario_entities
from common.world import iter_assets, iter_entities, iter_relationships, run_id
from create_cim_events import export_cim
from create_story import export_story, sha256_file


CONTEXT = (
    "assets.jsonl", "entities.jsonl", "relationships.jsonl",
    "identities.jsonl", "access-policies.jsonl", "data-objects.jsonl",
    "compliance.jsonl", "compliance-followup.jsonl", "detection-rules.jsonl",
)
TRUTH = (
    "recon-truth.json", "ingress-truth.json", "identity-truth.json",
    "endpoint-truth.json", "data-access-truth.json", "response-truth.json",
    "timeline.jsonl", "state-changes.jsonl", "identity-state.jsonl",
    "sensor-coverage.jsonl", "detection-decisions.jsonl",
)
EXPECTED = {"alerts.cim.jsonl": "expected-alerts.jsonl",
            "case-actions.cim.jsonl": "expected-case-actions.jsonl"}
UNMAPPED = {"ingress-zeek-ssl.jsonl"}
XML_VIEWS = {"windows-security.xml", "sysmon.xml", "windows-file.xml"}
# The same eight DNS transactions appear in recon.jsonl and dns.log.
OMIT_PROJECTIONS = {"dns.cim.jsonl", *EXPECTED}


def _copy(source, target, files):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    files[target.relative_to(target.parents[1]).as_posix()] = {
        "bytes": target.stat().st_size, "sha256": sha256_file(target)}


def _publish_directory(staged, target):
    """Allow transient Windows file scanners to release a new package."""
    for attempt in range(5):
        try:
            os.replace(staged, target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == 4:
                raise
            time.sleep(0.05 * 2 ** attempt)


def export_dataset(seed, start, duration_minutes, campaign_count, host_count, output_dir,
                   target_events=10000, scenario_file=None):
    """Publish a fixed reference story or an authored scenario in one CIM event view."""
    if target_events < 1:
        raise ValueError("--target-events must be positive")
    spec = load_scenario(scenario_file) if scenario_file else None
    recipe_hash = (hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":"))
                                  .encode()).hexdigest() if spec else "")
    mix = spec.get("background_mix", DEFAULT_MIX) if spec else DEFAULT_MIX
    target = Path(output_dir).resolve()
    if target.exists():
        raise ValueError(f"Output directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{target.name}.", dir=target.parent) as temp:
        root = Path(temp)
        source = root / "source"
        projection = root / "projection"
        publish = root / "publish"
        publish.mkdir()
        if spec:
            if start.tzinfo is None or duration_minutes <= 0:
                raise ValueError("Scenario needs timezone-aware start and positive duration")
            source.mkdir()
            for name, records in (
                    ("assets.jsonl", iter_assets(seed, host_count)),
                    ("entities.jsonl", iter_entities()),
                    ("relationships.jsonl", iter_relationships(seed, host_count)),
                    ("identities.jsonl", iter_identities())):
                export_records(source / name, records, "jsonl")
            source_manifest = {
                "run_id": run_id(seed, start.astimezone(timezone.utc)
                                 .isoformat(timespec="seconds").replace("+00:00", "Z"),
                                 host_count, duration_minutes, 0, recipe_hash),
                "start_time": start.astimezone(timezone.utc)
                .isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
        else:
            source_manifest = export_story(seed, start, duration_minutes,
                                           campaign_count, host_count, source)
        dataset_id = "dataset-" + hashlib.sha256(json.dumps(
            [source_manifest["run_id"], target_events, BACKGROUND_VERSION,
             recipe_hash, mix],
            separators=(",", ":")).encode()).hexdigest()[:16]
        if not spec:
            unclassified = set(source_manifest["files"]) - (
                set(SOURCES) | set(CONTEXT) | set(TRUTH) | UNMAPPED | XML_VIEWS)
            if unclassified:
                raise ValueError(f"Unclassified source files: {sorted(unclassified)}")
        files = {}
        if spec:
            # Tailored scenarios use the shared world directly, without generating
            # the fixed investigation or including its answer key.
            entities_path = source / "entities.jsonl"
            existing = [json.loads(line) for line in entities_path.read_text(
                encoding="utf-8").splitlines()]
            assets = [json.loads(line) for line in
                      (source / "assets.jsonl").read_text(encoding="utf-8").splitlines()]
            merged = merge_scenario_entities(spec, assets, existing)
            custom = merged[len(existing):]
            if custom:
                with entities_path.open("a", encoding="utf-8", newline="\n") as stream:
                    for row in custom:
                        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            def read_context(name):
                return [json.loads(line) for line in
                        (source / name).read_text(encoding="utf-8").splitlines()]
            planted, steps = compile_scenario(
                spec, start, duration_minutes, read_context("assets.jsonl"),
                read_context("entities.jsonl"), read_context("identities.jsonl"),
                dataset_id)
            cim_manifest = None
            context_names = CONTEXT[:4]
            truth_names = ()
        else:
            cim_manifest = export_cim(source, projection)
            planted = [json.loads(line) for path in sorted(
                projection.glob("*.cim.jsonl")) if path.name not in OMIT_PROJECTIONS
                for line in path.read_text(encoding="utf-8").splitlines()]
            planted.sort(key=lambda row: (row["time"], row.get("event_id", "")))
            context_names, truth_names = CONTEXT, TRUTH
        planted_count = len(planted)
        if target_events < planted_count:
            raise ValueError(f"Requested {target_events} events, but the linked story has "
                             f"{planted_count}; increase --target-events")
        background_count = target_events - planted_count
        streams, origin_counts = publish_events(
            publish, root / "spools", planted,
            background_events(seed, start, duration_minutes, background_count,
                              source / "assets.jsonl", source / "entities.jsonl",
                              dataset_id, mix))
        event_count = sum(streams.values())
        if event_count != target_events or sum(origin_counts["background"].values()) != background_count:
            raise ValueError("Published event counts do not match the requested target")
        for name in streams:
            path = publish / "events" / name
            files[f"events/{name}"] = {
                "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        for name in context_names:
            _copy(source / name, publish / "context" / name, files)
        for name in truth_names:
            _copy(source / name, publish / "truth" / name, files)
        if spec:
            truth_path = publish / "truth" / "scenario-truth.json"
            truth_path.parent.mkdir(parents=True, exist_ok=True)
            truth_path.write_text(json.dumps({
                "scenario_id": spec["id"], "title": spec["title"],
                "description": spec.get("description", ""), "steps": steps,
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            files["truth/scenario-truth.json"] = {
                "bytes": truth_path.stat().st_size, "sha256": sha256_file(truth_path)}
        else:
            for projected, name in EXPECTED.items():
                source_name = projected.replace(".cim.jsonl", ".jsonl")
                _copy(source / source_name, publish / "truth" / name, files)
        manifest = {
            "format": "sec-data-cim-events-v2",
            "run_id": dataset_id,
            "story_run_id": None if spec else source_manifest["run_id"],
            "scenario_id": spec["id"] if spec else None,
            "scenario_sha256": recipe_hash if spec else None,
            "background_version": BACKGROUND_VERSION,
            "background_mix": mix,
            "seed": seed,
            "start_time": source_manifest["start_time"],
            "duration_minutes": duration_minutes,
            "cim_reference_version": (cim_manifest["cim_reference_version"]
                                      if cim_manifest else CIM_VERSION),
            "event_sourcetype": "secdata:cim:json",
            "event_records": event_count,
            "planted_records": planted_count,
            "background_records": background_count,
            "source_counts": streams,
            "origin_counts": origin_counts,
            "source_observations": (cim_manifest["source_records"]
                                    if cim_manifest else planted_count),
            "excluded": ({} if spec else {
                "duplicate_dns_view": cim_manifest["files"]["dns.cim.jsonl"]["cim_records"],
                "scripted_alert_and_case_outcomes": sum(
                    cim_manifest["files"][name]["cim_records"] for name in EXPECTED),
                "unmapped_source_observations": cim_manifest["unmapped_records"],
                "unmapped_tls_observations": source_manifest["files"][
                    "ingress-zeek-ssl.jsonl"]["records"],
            }),
            "files": dict(sorted(files.items())),
        }
        if not spec and planted_count + sum(manifest["excluded"][name] for name in (
                "duplicate_dns_view", "scripted_alert_and_case_outcomes",
                "unmapped_source_observations")) != cim_manifest["source_records"]:
            raise ValueError("Published event counts do not reconcile with source observations")
        (publish / "dataset-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
        _publish_directory(publish, target)
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42,
                        help="Repeatable run seed (default: 42)")
    parser.add_argument("--start-time", required=True,
                        help="ISO 8601 start time with timezone, for example 2026-10-22T12:00:00Z")
    parser.add_argument("--duration-minutes", type=int, default=60,
                        help="Event window in minutes; spaces reference operations (default: 60)")
    parser.add_argument("--campaign-count", type=int, default=1,
                        help="Reference story reconnaissance sets; ignored with --scenario-file (default: 1)")
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT,
                        help=f"Inventory size, at least {DEFAULT_HOST_COUNT} (default: {DEFAULT_HOST_COUNT})")
    parser.add_argument("--target-events", type=int, default=10000,
                        help="Exact published event count, at least the planted count (default: 10000)")
    parser.add_argument("--scenario-file",
                        help="Versioned JSON story; replaces the fixed planted investigation")
    parser.add_argument("--output-dir", required=True,
                        help="New directory for events, context, truth, and manifest")
    args = parser.parse_args()
    try:
        start = datetime.fromisoformat(parse_times([args.start_time])[0].replace("Z", "+00:00"))
        result = export_dataset(args.seed, start, args.duration_minutes,
                                args.campaign_count, args.host_count, args.output_dir,
                                args.target_events, args.scenario_file)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(f"Wrote {result['event_records']} CIM-shaped events to "
          f"{Path(args.output_dir).resolve() / 'events'}")


if __name__ == "__main__":
    main()
