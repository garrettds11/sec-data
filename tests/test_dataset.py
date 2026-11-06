"""Check source streams, authored scenarios, and deterministic package counts."""

import copy
import hashlib
import json
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common.identity import iter_identities
from common.scenario import compile_scenario, load_scenario
from common.world import iter_assets, iter_entities
from create_dataset import export_dataset

START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
SAMPLE = Path(__file__).parents[1] / "scenarios" / "file-collection.json"


def rows(root):
    return {
        path.name: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for path in sorted((root / "events").glob("*.jsonl"))
    }


class DatasetTests(unittest.TestCase):
    def test_reference_story_and_background_share_source_streams(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            target = Path(temp) / "dataset"
            manifest = export_dataset(42, START, 60, 1, 23, target, target_events=10000)
            streams = rows(target)
            all_rows = [row for group in streams.values() for row in group]
            self.assertEqual(len(all_rows), manifest["event_records"])
            self.assertEqual(len(all_rows), 10000)
            self.assertEqual(manifest["planted_records"], 274)
            self.assertEqual(manifest["background_records"], 9726)
            self.assertFalse((target / "events" / "background-session.jsonl").exists())
            self.assertFalse((target / "events" / "recon.jsonl").exists())
            ids = [r["event_id"] for r in all_rows if "event_id" in r]
            self.assertEqual(len(set(ids)), len(ids))
            self.assertTrue(all(r["sec_data_source"] == name for name, group
                                in streams.items() for r in group))
            self.assertTrue(all(group == sorted(group, key=lambda r:
                                (r["time"], r.get("event_id", "")))
                                for group in streams.values()))
            self.assertGreater(manifest["source_counts"]["web-auth.jsonl"], 1000)
            self.assertGreater(manifest["source_counts"]["windows-file.jsonl"], 100)
            self.assertGreater(manifest["source_counts"]["egress-firewall.jsonl"], 100)
            self.assertEqual(sum(manifest["origin_counts"]["background"].values()), 9726)
            self.assertTrue(all("scenario_id" not in row and "ground_truth" not in row
                                for row in all_rows))
            fixture = Path(__file__).parent / "fixtures" / "cim-story-42"
            planted = [json.loads(line) for path in fixture.glob("*.cim.jsonl")
                       if path.name not in {"dns.cim.jsonl", "alerts.cim.jsonl",
                                            "case-actions.cim.jsonl"}
                       for line in path.read_text(encoding="utf-8").splitlines()]
            def without_source(row):
                return json.dumps({key: value for key, value in row.items()
                                   if key != "sec_data_source"}, sort_keys=True)
            actual = Counter(without_source(row) for row in all_rows)
            for expected in planted:
                self.assertGreater(actual[without_source(expected)], 0)
                actual[without_source(expected)] -= 1
            for name, info in manifest["files"].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(),
                                 info["sha256"])

    def test_authored_story_uses_same_generator_without_fixed_truth(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root = Path(temp)
            first = export_dataset(42, START, 60, 1, 23, root / "first",
                                   target_events=1000, scenario_file=SAMPLE)
            second = export_dataset(42, START, 60, 1, 23, root / "second",
                                    target_events=1000, scenario_file=SAMPLE)
            self.assertEqual(first, second)
            self.assertEqual(first["planted_records"], 7)
            self.assertEqual(first["background_records"], 993)
            self.assertEqual(first["scenario_id"], "file-collection-example")
            self.assertEqual(first["origin_counts"]["planted"]["ingress-zeek-http.jsonl"], 1)
            self.assertEqual(first["source_counts"]["response-firewall.jsonl"], 1)
            self.assertFalse((root / "first" / "truth" / "recon-truth.json").exists())
            truth = json.loads((root / "first" / "truth" / "scenario-truth.json").read_text())
            self.assertEqual(len(truth["steps"]), 6)
            all_rows = [row for group in rows(root / "first").values() for row in group]
            event_ids = {event_id for step in truth["steps"] for event_id in step["event_ids"]}
            self.assertEqual(sum(row["event_id"] in event_ids for row in all_rows), 7)
            self.assertFalse(any("file-collection-example" in json.dumps(row)
                                 for row in all_rows))
            self.assertTrue(any(row.get("dest") == "192.0.2.222" for row in all_rows))
            entities = (root / "first" / "context" / "entities.jsonl").read_text()
            self.assertIn("entity-transfer-destination", entities)
            alternate = load_scenario(SAMPLE)
            alternate["id"] = "different-story"
            alternate["steps"] = [alternate["steps"][0]]
            path = root / "alternate.json"
            path.write_text(json.dumps(alternate), encoding="utf-8")
            other = export_dataset(42, START, 60, 1, 23, root / "other",
                                   target_events=1000, scenario_file=path)
            self.assertEqual(other["planted_records"], 1)
            self.assertNotEqual(other["run_id"], first["run_id"])
            self.assertFalse((root / "other" / "events" / "response-firewall.jsonl").exists())

    def test_invalid_reference_rejected_before_publication(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root = Path(temp)
            spec = load_scenario(SAMPLE)
            spec["steps"][0]["observations"][0]["fields"]["dest"] = {
                "ref": "asset:missing-host:ip"}
            path = root / "bad.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown scenario reference"):
                export_dataset(42, START, 60, 1, 23, root / "dataset",
                               target_events=100, scenario_file=path)
            self.assertFalse((root / "dataset").exists())

    def test_scenario_compiler_rejects_invalid_semantics(self):
        base = load_scenario(SAMPLE)
        assets = list(iter_assets(42, 23))
        entities = list(iter_entities()) + base["entities"]
        identities = list(iter_identities())
        def compile_spec(spec):
            return compile_scenario(spec, START, 60, assets, entities, identities,
                                    "validation-run")
        bad_source = copy.deepcopy(base)
        bad_source["steps"][0]["observations"][0]["dataset"] = "Endpoint.Processes"
        with self.assertRaisesRegex(ValueError, "Unsupported source/dataset"):
            compile_spec(bad_source)
        bad_bytes = copy.deepcopy(base)
        bad_bytes["steps"][4]["observations"][0]["fields"]["bytes"] = 7
        with self.assertRaisesRegex(ValueError, "Network bytes"):
            compile_spec(bad_bytes)
        truth_leak = copy.deepcopy(base)
        truth_leak["steps"][0]["observations"][0]["fields"]["malicious"] = True
        with self.assertRaisesRegex(ValueError, "truth-only"):
            compile_spec(truth_leak)
        out_of_order = copy.deepcopy(base)
        out_of_order["steps"][1]["offset_seconds"] = 50
        with self.assertRaisesRegex(ValueError, "out-of-order"):
            compile_spec(out_of_order)


if __name__ == "__main__":
    unittest.main()
