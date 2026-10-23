import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import create_story
from common.identity import WINDOWS_EVENT_NS, render_windows_xml
from common.story_validation import validate_bundle


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class EndpointTests(unittest.TestCase):
    def test_sysmon_tree_joins_session_recon_and_file_creation(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            manifest = create_story.export_story(42, START, 60, 1, 23, root)
            self.assertEqual(manifest["validation"]["endpoint_events"], 15)
            events = rows(root / "sysmon.jsonl")
            coverage = rows(root / "sensor-coverage.jsonl")
            truth = json.loads((root / "endpoint-truth.json").read_text(encoding="utf-8"))
            self.assertEqual(len([row for row in coverage if row["enabled"]]), 1)
            self.assertEqual({row["Computer"] for row in events},
                             {"prod-file-01.corp.example.local"})
            self.assertEqual({row["EventCode"] for row in events}, {1, 3, 5, 11, 13})
            processes = {row["ProcessGuid"]: row for row in events if row["EventCode"] == 1}
            for row in processes.values():
                if "ParentProcessGuid" in row:
                    self.assertLess(processes[row["ParentProcessGuid"]]["TimeCreated"],
                                    row["TimeCreated"])
            network_links = [link for link in truth["interactions"] if link["event_code"] == 3]
            recon = {row["event_id"]: row for row in rows(root / "recon.jsonl")}
            self.assertEqual(len(network_links), 4)
            self.assertTrue(all(recon[link["related_recon_event_id"]]["event_type"] ==
                                "network_connection" for link in network_links))
            self.assertTrue(any(row["EventCode"] == 11 and "inventory-summary" in
                                row["TargetFilename"] for row in events))
            xml = ET.fromstring((root / "sysmon.xml").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(xml.findtext("e:System/e:EventID", namespaces={"e": WINDOWS_EVENT_NS}),
                             "1")

    def test_validator_rejects_network_event_that_conflicts_with_recon(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            events = rows(root / "sysmon.jsonl")
            network = next(row for row in events if row["EventCode"] == 3)
            network["DestinationIp"] = "192.0.2.99"
            (root / "sysmon.jsonl").write_text("".join(json.dumps(row) + "\n" for row in events),
                                                  encoding="utf-8")
            (root / "sysmon.xml").write_text("".join(render_windows_xml(row) + "\n" for row in events),
                                               encoding="utf-8")
            truth = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "Sysmon network observation differs from recon"):
                validate_bundle(root, truth)


if __name__ == "__main__":
    unittest.main()
