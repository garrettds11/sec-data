#!/usr/bin/env python3
"""Publish one linked run with CIM-shaped analyst events and separate context."""

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from common.assets import DEFAULT_HOST_COUNT
from common.background import VERSION as BACKGROUND_VERSION, iter_events as background_events
from common.cim import SOURCES
from common.export import export_records, parse_times
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


def export_dataset(seed, start, duration_minutes, campaign_count, host_count, output_dir,
                   target_events=10000):
    """Build and validate source observations privately; publish one event view."""
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
        source_manifest = export_story(seed, start, duration_minutes,
                                       campaign_count, host_count, source)
        dataset_id = "dataset-" + hashlib.sha256(json.dumps(
            [source_manifest["run_id"], target_events, BACKGROUND_VERSION],
            separators=(",", ":")).encode()).hexdigest()[:16]
        unclassified = set(source_manifest["files"]) - (
            set(SOURCES) | set(CONTEXT) | set(TRUTH) | UNMAPPED | XML_VIEWS)
        if unclassified:
            raise ValueError(f"Unclassified source files: {sorted(unclassified)}")
        cim_manifest = export_cim(source, projection)
        files = {}
        event_count = 0
        for path in sorted(projection.glob("*.cim.jsonl")):
            if path.name in OMIT_PROJECTIONS:
                continue
            name = path.name.replace(".cim.jsonl", ".jsonl")
            destination = publish / "events" / name
            _copy(path, destination, files)
            event_count += cim_manifest["files"][path.name]["cim_records"]
        if target_events < event_count:
            raise ValueError(f"Requested {target_events} events, but the linked story has "
                             f"{event_count}; increase --target-events")
        background_count = target_events - event_count
        if background_count:
            background_path = publish / "events" / "background-session.jsonl"
            generated = export_records(
                background_path,
                background_events(seed, start, duration_minutes, background_count,
                                  source / "assets.jsonl", source / "entities.jsonl",
                                  dataset_id),
                "jsonl")
            files["events/background-session.jsonl"] = {
                "bytes": background_path.stat().st_size,
                "sha256": sha256_file(background_path)}
            event_count += generated
        for name in CONTEXT:
            _copy(source / name, publish / "context" / name, files)
        for name in TRUTH:
            _copy(source / name, publish / "truth" / name, files)
        for projected, name in EXPECTED.items():
            source_name = projected.replace(".cim.jsonl", ".jsonl")
            _copy(source / source_name, publish / "truth" / name, files)
        manifest = {
            "format": "sec-data-cim-events-v1",
            "run_id": dataset_id,
            "story_run_id": source_manifest["run_id"],
            "background_version": BACKGROUND_VERSION,
            "seed": seed,
            "start_time": source_manifest["start_time"],
            "cim_reference_version": cim_manifest["cim_reference_version"],
            "event_sourcetype": "secdata:cim:json",
            "event_records": event_count,
            "background_records": background_count,
            "source_observations": cim_manifest["source_records"],
            "excluded": {
                "duplicate_dns_view": cim_manifest["files"]["dns.cim.jsonl"]["cim_records"],
                "scripted_alert_and_case_outcomes": sum(
                    cim_manifest["files"][name]["cim_records"] for name in EXPECTED),
                "unmapped_source_observations": cim_manifest["unmapped_records"],
                "unmapped_tls_observations": source_manifest["files"][
                    "ingress-zeek-ssl.jsonl"]["records"],
            },
            "files": dict(sorted(files.items())),
        }
        if event_count - background_count + sum(manifest["excluded"][name] for name in (
                "duplicate_dns_view", "scripted_alert_and_case_outcomes",
                "unmapped_source_observations")) != cim_manifest["source_records"]:
            raise ValueError("Published event counts do not reconcile with source observations")
        (publish / "dataset-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
        os.replace(publish, target)
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42,
                        help="Repeatable run seed (default: 42)")
    parser.add_argument("--start-time", required=True,
                        help="ISO 8601 start time with timezone, for example 2026-10-22T12:00:00Z")
    parser.add_argument("--duration-minutes", type=int, default=60,
                        help="Event window in minutes; also spaces planted operations (default: 60)")
    parser.add_argument("--campaign-count", type=int, default=1,
                        help="Sets of four planted reconnaissance operations (default: 1)")
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT,
                        help=f"Inventory size, at least {DEFAULT_HOST_COUNT} (default: {DEFAULT_HOST_COUNT})")
    parser.add_argument("--target-events", type=int, default=10000,
                        help="Exact published event count, at least the planted count (default: 10000)")
    parser.add_argument("--output-dir", required=True,
                        help="New directory for events, context, truth, and manifest")
    args = parser.parse_args()
    try:
        start = datetime.fromisoformat(parse_times([args.start_time])[0].replace("Z", "+00:00"))
        result = export_dataset(args.seed, start, args.duration_minutes,
                                args.campaign_count, args.host_count, args.output_dir,
                                args.target_events)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(f"Wrote {result['event_records']} CIM-shaped events to "
          f"{Path(args.output_dir).resolve() / 'events'}")


if __name__ == "__main__":
    main()
