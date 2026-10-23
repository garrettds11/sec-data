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


class ResponseTests(unittest.TestCase):
    def test_alert_availability_suppression_and_containment_effect(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            manifest = create_story.export_story(42, START, 60, 1, 23, root)
            self.assertEqual(manifest["validation"]["response_alerts"], 2)
            alerts = rows(root / "alerts.jsonl")
            decisions = rows(root / "detection-decisions.jsonl")
            actions = rows(root / "case-actions.jsonl")
            retry = rows(root / "response-firewall.jsonl")[0]
            truth = json.loads((root / "response-truth.json").read_text(encoding="utf-8"))
            self.assertEqual(len([row for row in decisions if row["outcome"] == "suppressed"]), 1)
            self.assertTrue(all(ref["available_at"] <= alert["fired_at"]
                                for alert in alerts for ref in alert["evidence"]))
            self.assertEqual(actions[0]["action"], "opened")
            self.assertEqual(actions[-1]["action"], "verified")
            review = next(row for row in actions if row["action"] == "reviewed")
            self.assertEqual({item["source"] for item in review["context"]},
                             {"relationships", "edge-proxy", "web-auth", "windows-security", "sysmon"})
            self.assertLess(truth["containment_effective_at"], retry["time"])
            self.assertEqual(retry["action"], "block")
            self.assertEqual(retry["bytes_out"], 0)
            self.assertNotIn("object_id", json.dumps(alerts))

    def test_validator_rejects_alert_fired_before_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "alerts.jsonl"
            alerts = rows(path)
            target = next(row for row in alerts if row["rule_id"] == "sensitive-read-outbound")
            target["fired_at"] = target["first_observed_at"]
            path.write_text("".join(json.dumps(row) + "\n" for row in alerts), encoding="utf-8")
            recon = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "deterministic rule: alerts.jsonl"):
                validate_bundle(root, recon)


if __name__ == "__main__":
    unittest.main()
