"""Regression checks for Splunk Eventgen CSV metadata."""

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "splunk_eventgen" / "prepare_sample.py"


class EventgenSampleTests(unittest.TestCase):
    def test_preparation_preserves_raw_events_with_or_without_device(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            events = run / "events"
            events.mkdir()
            source = "sysmon.jsonl"
            device_fields = [{"dvc": "prod-file-01"}, {}, {"dvc": ""}, {"dvc": None}]
            original_rows = [
                json.dumps({
                    "time": "2024-11-12T08:00:00.000Z",
                    "event_id": str(number),
                    "sec_data_source": source,
                    "synthetic": True,
                    **fields,
                })
                for number, fields in enumerate(device_fields)
            ]
            event_file = events / source
            event_file.write_text("\n".join(original_rows) + "\n", encoding="utf-8")
            input_bytes = event_file.read_bytes()
            (run / "dataset-manifest.json").write_text(json.dumps({
                "scenario_id": "example",
                "event_sourcetype": "secdata:cim:json",
                "event_records": len(original_rows),
                "source_counts": {source: len(original_rows)},
            }), encoding="utf-8")

            output = run / "replay.csv"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(run), str(output), "--scenario-id", "example"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with output.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([row["host"] for row in rows],
                             ["prod-file-01", "unknown-sysmon", "unknown-sysmon", "unknown-sysmon"])
            self.assertEqual([row["source"] for row in rows], [source] * len(original_rows))
            self.assertEqual([row["_raw"] for row in rows], original_rows)
            self.assertEqual(event_file.read_bytes(), input_bytes)
