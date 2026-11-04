"""Check the published single-view CIM dataset as a usable analyst input."""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from create_dataset import export_dataset


class DatasetTests(unittest.TestCase):
    def test_published_events_have_one_cim_view(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            target = Path(temp) / "dataset"
            manifest = export_dataset(42, datetime(2026, 10, 22, 12,
                                                   tzinfo=timezone.utc),
                                      60, 1, 23, target)
            events = [json.loads(line)
                      for path in sorted((target / "events").glob("*.jsonl"))
                      for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), manifest["event_records"])
            self.assertEqual(len(events), 274)
            self.assertEqual(len({event["sec_data_cim_dataset"] for event in events}), 10)
            self.assertTrue(all({"time", "synthetic", "sec_data_source",
                                 "sec_data_cim_dataset"} <= event.keys()
                                for event in events))
            self.assertEqual(sum(event["sec_data_cim_dataset"] ==
                                 "Network_Resolution.DNS" for event in events), 8)
            self.assertFalse((target / "events" / "alerts.jsonl").exists())
            self.assertFalse((target / "events" / "case-actions.jsonl").exists())
            self.assertTrue((target / "truth" / "expected-alerts.jsonl").exists())
            self.assertTrue((target / "context" / "assets.jsonl").exists())
            self.assertFalse(list(target.rglob("*.xml")))
            self.assertEqual(set(path.relative_to(target).as_posix()
                                 for path in target.rglob("*.jsonl")
                                 if path.parent.name == "events"),
                             {name for name in manifest["files"]
                              if name.startswith("events/")})
            for name, info in manifest["files"].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(),
                                 info["sha256"])
            fixture = Path(__file__).parent / "fixtures" / "cim-story-42"
            for event_file in (target / "events").glob("*.jsonl"):
                expected = fixture / event_file.name.replace(".jsonl", ".cim.jsonl")
                self.assertEqual(event_file.read_bytes(), expected.read_bytes())
            self.assertEqual(json.loads((target / "dataset-manifest.json").read_text()),
                             manifest)


if __name__ == "__main__":
    unittest.main()
