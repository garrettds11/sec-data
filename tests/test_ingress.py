import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import create_story
from common.story_validation import validate_bundle


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class IngressTests(unittest.TestCase):
    def test_allowed_blocked_nat_and_tls_visibility(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            manifest = create_story.export_story(42, START, 60, 1, 23, root)
            self.assertEqual(manifest["validation"]["ingress_firewall_events"], 4)
            self.assertEqual(manifest["validation"]["ingress_flows"], 3)
            self.assertEqual(manifest["validation"]["ingress_tls"], 1)
            truth = json.loads((root / "ingress-truth.json").read_text(encoding="utf-8"))
            firewall = rows(root / "ingress-firewall.jsonl")
            blocked = next(row for row in truth["interactions"] if row["application_event_id"] is None)
            self.assertEqual(firewall[blocked["firewall_index"]]["action"], "block")
            self.assertIsNone(blocked["zeek_uid"])
            allowed_public = [row for row in truth["interactions"] if row["public_destination"]
                              and row["application_event_id"]]
            self.assertEqual(len(allowed_public), 2)
            self.assertTrue(all(row["public_destination"].startswith("198.51.100.") and
                                row["translated_destination"].startswith("10.")
                                for row in allowed_public))
            tls = rows(root / "ingress-zeek-ssl.jsonl")
            self.assertEqual(len(tls), 1)
            self.assertNotIn("uri", tls[0])
            self.assertTrue(any(row["uri"] == "/" and row["server_port"] == 443
                                for row in rows(root / "edge-proxy.jsonl")))

    def test_validator_rejects_downstream_observation_for_block(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "ingress-truth.json"
            truth = json.loads(path.read_text(encoding="utf-8"))
            blocked = next(row for row in truth["interactions"] if row["application_event_id"] is None)
            blocked["zeek_uid"] = "fabricated-flow"
            path.write_text(json.dumps(truth), encoding="utf-8")
            recon = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "blocked ingress has downstream evidence"):
                validate_bundle(root, recon)


if __name__ == "__main__":
    unittest.main()
