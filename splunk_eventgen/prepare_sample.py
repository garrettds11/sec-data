#!/usr/bin/env python3
"""Convert the modeled event streams in one sec-data run to an Eventgen sample."""

import argparse
import csv
import json
import re
from heapq import merge
from pathlib import Path

EVENT_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


def read_events(path, expected_count):
    previous = "", ""
    count = 0
    fallback_host = f"unknown-{path.stem}"
    with path.open(encoding="utf-8") as stream:
        for count, line in enumerate(stream, 1):
            raw = line.rstrip("\r\n")
            event = json.loads(raw)
            timestamp = event["time"]
            key = timestamp, event["event_id"]
            if not EVENT_TIME.fullmatch(timestamp) or key < previous:
                raise ValueError(f"{path.name}:{count}: expected sorted UTC millisecond timestamps")
            if event["sec_data_source"] != path.name or event["synthetic"] is not True:
                raise ValueError(f"{path.name}:{count}: expected a synthetic event from this source")
            device = event.get("dvc")
            host = device if isinstance(device, str) and device.strip() else fallback_host
            previous = key
            yield key, host, path.name, raw
    if count != expected_count:
        raise ValueError(f"{path.name}: expected {expected_count} events, read {count}")


def prepare_sample(dataset_dir, output, scenario_id):
    manifest = json.loads((dataset_dir / "dataset-manifest.json").read_text(encoding="utf-8"))
    if manifest["scenario_id"] != scenario_id:
        raise ValueError(f"Expected scenario {scenario_id}, got {manifest['scenario_id']}")
    if manifest["event_sourcetype"] != "secdata:cim:json":
        raise ValueError("Expected secdata:cim:json events")
    counts = manifest["source_counts"]
    event_dir = dataset_dir / "events"
    if not counts or set(counts) != {path.name for path in event_dir.glob("*.jsonl")}:
        raise ValueError("Event files do not match the manifest source inventory")
    if sum(counts.values()) != manifest["event_records"]:
        raise ValueError("Manifest source counts do not add up to the event total")

    inputs = [read_events(event_dir / name, counts[name]) for name in sorted(counts)]
    output.parent.mkdir(parents=True, exist_ok=True)
    stream = output.open("x", encoding="utf-8", newline="")
    try:
        with stream:
            writer = csv.writer(stream)
            writer.writerow(("host", "source", "_raw"))
            for _, host, source, raw in merge(*inputs, key=lambda record: record[0]):
                writer.writerow((host, source, raw))
    except BaseException:
        output.unlink()
        raise
    finally:
        for events in inputs:
            events.close()
    return manifest["event_records"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_dir", type=Path, help="Generated run directory")
    parser.add_argument("output", type=Path, help="New Eventgen CSV file")
    parser.add_argument("--scenario-id", required=True, help="Expected ID from the scenario JSON")
    args = parser.parse_args()
    try:
        count = prepare_sample(args.dataset_dir, args.output, args.scenario_id)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Could not prepare Eventgen sample: {error}\n")
    print(f"Prepared {count} events in {args.output}")


if __name__ == "__main__":
    main()
