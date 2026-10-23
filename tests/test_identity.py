import json
import random
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import create_story
from common.assets import build_hosts
from common.identity import WINDOWS_EVENT_NS, generate, render_windows_xml
from common.story_validation import validate_bundle


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


class IdentityTests(unittest.TestCase):
    def test_policy_change_explains_denial_then_success(self):
        hosts = {host["short"]: host for host in build_hosts(random.Random(42))}
        first = generate(42, START, 60, 1, hosts)
        self.assertEqual(first, generate(42, START, 60, 1, hosts))
        truth = first["truth"]
        grant = next(c for c in truth["state_changes"] if c["kind"] == "group_membership")
        operator = [event for event in truth["interactions"] if
                    event["identity_id"] == "identity-operator-01" and
                    event["source"] == "windows-security" and
                    event.get("policy_id") == "policy-file-operator"]
        self.assertEqual([(event["outcome"], event["at"] < grant["effective_at"])
                          for event in operator], [("failure", True), ("success", False)])
        self.assertEqual([row["EventCode"] for row in first["windows_events"]],
                         [4624, 4624, 4625, 4728, 4624, 4624])
        grant_xml = ET.fromstring(render_windows_xml(first["windows_events"][3]))
        ns = {"e": WINDOWS_EVENT_NS}
        self.assertEqual(grant_xml.findtext("e:System/e:EventID", namespaces=ns), "4728")
        self.assertEqual({item.attrib["Name"]: item.text for item in
                          grant_xml.findall("e:EventData/e:Data", ns)}["SubjectLogonId"],
                         first["windows_events"][1]["TargetLogonId"])
        self.assertTrue(all("password" not in json.dumps(row).lower()
                            for row in first["windows_events"]))
        self.assertEqual(next(s for s in truth["sessions"] if
                              s["identity_id"] == "identity-analyst-01")["linked_recon_operation_id"],
                         "operation-0001")

    def test_bundle_validator_rejects_privilege_timeline_tamper(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "identity-state.jsonl"
            changes = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            grant = next(row for row in changes if row["kind"] == "group_membership")
            grant["effective_at"] = "2026-10-22T12:50:00.000Z"
            path.write_text("".join(json.dumps(row) + "\n" for row in changes), encoding="utf-8")
            truth = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "identity state differs from truth"):
                validate_bundle(root, truth)


if __name__ == "__main__":
    unittest.main()
