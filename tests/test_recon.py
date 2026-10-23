import json
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import create_recon_events as recon
from common.export import export_records


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


class ReconTests(unittest.TestCase):
    def test_reproducible_truth_alignment_and_schema(self):
        first, truth = recon.generate(42, START, 60, 1)
        events = list(first)
        again, truth_again = recon.generate(42, START, 60, 1)
        self.assertEqual(events, list(again))
        self.assertEqual(truth, truth_again)
        self.assertEqual({x["family"] for x in truth["operations"]}, set(recon.FAMILIES))
        ids = [e["event_id"] for e in events]
        by_id = {e["event_id"]: e for e in events}
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), {i for op in truth["operations"] for i in op["event_ids"]})
        for op in truth["operations"]:
            for link in op["interaction_links"]:
                if "caused_by" in link:
                    self.assertEqual(by_id[link["caused_by"]]["outcome"], "connected")
                    self.assertIn(by_id[link["event_id"]]["event_type"], ("http", "service_query"))
        self.assertEqual([e["timestamp"] for e in events], sorted(e["timestamp"] for e in events))
        self.assertTrue(all(e["synthetic"] and e["schema_version"] == recon.VERSION for e in events))
        for event in events:
            self.assertFalse({"scenario_id", "intent", "authorized", "techniques", "intended_tool"} & event.keys())

    def test_causality_and_visibility(self):
        records, truth = recon.generate(42, START, 60, 1, endpoint=False, http=False,
                                        nmap_indicator="behavior-only")
        events = list(records)
        self.assertFalse(any(e["event_type"] in ("process", "http") for e in events))
        self.assertGreater(truth["omitted_observations"]["unmonitored_endpoint"], 0)
        self.assertGreater(truth["omitted_observations"]["http_sensor_disabled"], 0)
        self.assertTrue(all(e["dst_ip"].startswith("198.51.100.") for e in events
                            if e["sensor_id"] == "perimeter-fw-01"))
        self.assertFalse(any(e.get("probe_type") == "syn" and e["event_type"] == "http" for e in events))
        self.assertTrue(all(e["bytes_in"] == 0 for e in events if e.get("outcome") == "blocked"))
        behavior, _ = recon.generate(42, START, 60, 1, nmap_indicator="behavior-only")
        self.assertFalse(any(e.get("executable") == "nmap" for e in behavior))

    def test_normalized_jsonl_and_evidence_refs(self):
        events, truth = recon.generate(42, START, 60, 1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path = Path(tmp) / "recon.jsonl"
            count = export_records(path, events, "jsonl")
            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(count, len(lines))
            self.assertEqual(Counter(e["event_type"] for e in lines)["service_query"], 4)
        catalog = json.loads((Path(recon.__file__).parent / "catalogs/recon/evidence-v1.json").read_text())
        known = {p["id"] for p in catalog["profiles"]}
        self.assertTrue(all(set(op["evidence_refs"]) <= known for op in truth["operations"]))
        self.assertTrue(all(op["calibration_status"] == "documented_behavior_only" for op in truth["operations"]))

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            recon.generate(42, START, 2, 1)
        with self.assertRaises(ValueError):
            recon.generate(42, START, 60, 101)
        with self.assertRaises(ValueError):
            recon.generate(42, START, 60, 1, background_sessions_per_minute=-1)
        quiet, _ = recon.generate(42, START, 60, 1, background_sessions_per_minute=0)
        self.assertFalse(any(e["event_type"] == "dns" for e in quiet))


if __name__ == "__main__":
    unittest.main()
