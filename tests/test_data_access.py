import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import create_story
from common.story_validation import validate_bundle


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class DataAccessTests(unittest.TestCase):
    def test_reads_uploads_and_controls_are_source_consistent(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            manifest = create_story.export_story(42, START, 60, 1, 23, root)
            self.assertEqual(manifest["validation"]["file_audit_events"], 3)
            self.assertEqual(manifest["validation"]["zeek_connections"], 3)
            self.assertEqual(manifest["validation"]["firewall_events"], 4)
            truth = json.loads((root / "data-access-truth.json").read_text(encoding="utf-8"))
            reads = {row["event_id"]: row for row in truth["accesses"]}
            transfers = {row["transfer_id"]: row for row in truth["transfers"]}
            self.assertEqual(reads[transfers["transfer-finance"]["related_read_event_id"]]["object_id"],
                             "object-finance-report")
            self.assertEqual(reads[transfers["transfer-backup"]["related_read_event_id"]]["object_id"],
                             "object-backup-manifest")
            self.assertEqual(transfers["transfer-blocked"]["result"], "block")
            self.assertIsNone(transfers["transfer-blocked"]["related_read_event_id"])
            self.assertEqual(transfers["transfer-admin-download"]["method"], "GET")
            self.assertTrue(all("object_id" not in row and "identity_id" not in row
                                for name in ("zeek-conn.jsonl", "zeek-http.jsonl",
                                             "egress-firewall.jsonl") for row in read(root / name)))

    def test_validator_rejects_denied_read_as_upload_source(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "data-access-truth.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            denied = next(row for row in data["accesses"] if row["result"] == "denied")
            upload = next(row for row in data["transfers"] if row["transfer_id"] == "transfer-finance")
            upload["related_read_event_id"] = denied["event_id"]
            path.write_text(json.dumps(data), encoding="utf-8")
            recon = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "successful matching read"):
                validate_bundle(root, recon)

    def test_validator_rejects_network_byte_divergence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "zeek-http.jsonl"
            events = read(path)
            upload = next(row for row in events if row["method"] == "POST" and
                          row["request_body_len"] == 4096)
            upload["request_body_len"] += 1
            path.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
            recon = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "transfer bytes differ"):
                validate_bundle(root, recon)


if __name__ == "__main__":
    unittest.main()
