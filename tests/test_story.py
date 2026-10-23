import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import create_story
from common.assets import DEFAULT_HOST_COUNT
from common.world import ENTITY_IPS, PUBLIC_IPS, SERVICES, iter_assets
from common.story_validation import validate_bundle, validate_export
from common.zeek_dns import render_dns


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class StoryTests(unittest.TestCase):
    def test_linked_bundle_is_repeatable_and_referentially_consistent(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            one = create_story.export_story(42, START, 60, 1, DEFAULT_HOST_COUNT, root / "one")
            two = create_story.export_story(42, START, 60, 1, DEFAULT_HOST_COUNT, root / "two")
            self.assertEqual(one, two)
            self.assertEqual(validate_export(root / "one"), one["validation"])
            self.assertEqual(json.loads((root / "one/run-manifest.json").read_text(encoding="utf-8")), one)
            self.assertEqual(create_story.sha256_file(root / "one/assets.jsonl"),
                             one["files"]["assets.jsonl"]["sha256"])
            self.assertEqual(one["host_count"], 23)
            self.assertGreater(one["filtered_vulnerability_findings"]["unsupported_service"], 0)
            self.assertEqual(one["files"]["dns.log"]["records"], 8)

            assets = rows(root / "one/assets.jsonl")
            entities = rows(root / "one/entities.jsonl")
            relationships = rows(root / "one/relationships.jsonl")
            vulnerabilities = rows(root / "one/vulnerability.jsonl")
            compliance = rows(root / "one/compliance.jsonl")
            vulnerability_followup = rows(root / "one/vulnerability-followup.jsonl")
            compliance_followup = rows(root / "one/compliance-followup.jsonl")
            changes = rows(root / "one/state-changes.jsonl")
            recon = rows(root / "one/recon.jsonl")
            dns = rows(root / "one/dns.log")
            timeline = rows(root / "one/timeline.jsonl")
            truth = json.loads((root / "one/recon-truth.json").read_text(encoding="utf-8"))
            by_name = {a["fqdn"]: a for a in assets}
            by_id = {a["asset_id"]: a for a in assets}
            self.assertEqual(len(by_id), 23)
            self.assertEqual(len({a["ip"] for a in assets + entities}), len(assets + entities))
            self.assertEqual({e["ip"] for e in entities}, set(ENTITY_IPS.values()))
            self.assertTrue(all(r["asset_id"] in by_id for r in relationships))
            self.assertEqual(len({r["relationship_id"] for r in relationships}), len(relationships))
            self.assertEqual({r["public_ip"] for r in relationships
                              if r["kind"] == "public_exposure"}, set(PUBLIC_IPS.values()))
            for finding in vulnerabilities:
                asset = by_name[finding["host_name"]]
                self.assertEqual(finding["host_ip"], asset["ip"])
                self.assertEqual(finding["asset_id"], asset["asset_id"])
                self.assertTrue(finding["network_port"] == 0 or
                                finding["network_port"] in SERVICES[asset["role"]])
            for finding in compliance:
                self.assertEqual(finding["host_ip"], by_name[finding["host_name"]]["ip"])
                self.assertEqual(finding["asset_id"], by_name[finding["host_name"]]["asset_id"])
            self.assertEqual(dns, [render_dns(e) for e in recon if e["event_type"] == "dns"])
            self.assertEqual(len(changes), 2)
            self.assertEqual({c["finding_type"] for c in changes}, {"vulnerability", "compliance"})
            self.assertTrue(all(c["asset_id"] in by_id for c in changes))
            for kind, before_rows, after_rows in (
                    ("vulnerability", vulnerabilities, vulnerability_followup),
                    ("compliance", compliance, compliance_followup)):
                self.assertEqual(len(before_rows), len(after_rows))
                selected = next(c for c in changes if c["finding_type"] == kind)
                baseline = {(r["asset_id"], r["finding_id"]): r for r in before_rows}
                followup = {(r["asset_id"], r["finding_id"]): r for r in after_rows}
                self.assertEqual(baseline.keys(), followup.keys())
                key = (selected["asset_id"], selected["finding_id"])
                self.assertEqual(baseline[key][f"{kind}_status"], selected["before"])
                self.assertEqual(followup[key][f"{kind}_status"], selected["after"])
                self.assertEqual(followup[key]["remediation_change_id"], selected["change_id"])
                for other_key in baseline.keys() - {key}:
                    self.assertEqual(baseline[other_key][f"{kind}_status"],
                                     followup[other_key][f"{kind}_status"])
            self.assertEqual(truth["run_id"], one["run_id"])
            self.assertEqual([item["at"] for item in timeline],
                             sorted(item["at"] for item in timeline))
            self.assertTrue(all(item["at"] > one["assessment_time"] for item in timeline[1:]))
            self.assertEqual([item["kind"] for item in timeline[-4:]],
                             ["state_change", "state_change", "followup_assessment", "case_action"])
            self.assertTrue(all(op["last_observation_at"] < one["remediation_time"]
                                for op in truth["operations"]))
            self.assertLess(one["remediation_time"], one["followup_time"])
            self.assertFalse(any("family" in e or "intent" in e for e in recon))

    def test_scaled_inventory_preserves_first_assets(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "scaled"
            manifest = create_story.export_story(42, START, 60, 1, 50, root)
            self.assertEqual(manifest["files"]["assets.jsonl"]["records"], 50)
            self.assertEqual(rows(root / "assets.jsonl")[:23], list(iter_assets(42, 23)))
            self.assertEqual(len(rows(root / "entities.jsonl")), 6)

    def test_rejects_existing_target_and_cleans_failed_staging(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "at least"):
                create_story.export_story(42, START, 60, 1, 22, root / "too-small")
            with patch.object(create_story.recon, "generate", side_effect=ValueError("fixture failure")):
                with self.assertRaisesRegex(ValueError, "fixture failure"):
                    create_story.export_story(42, START, 60, 1, 23, root / "failed")
            self.assertFalse((root / "failed").exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_validator_rejects_unplanned_followup_change(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp) / "story"
            create_story.export_story(42, START, 60, 1, 23, root)
            path = root / "vulnerability-followup.jsonl"
            findings = rows(path)
            changed = next(row for row in findings if "remediation_change_id" not in row)
            changed["vulnerability_status"] = "fixed" if changed["vulnerability_status"] != "fixed" else "open"
            path.write_text("".join(json.dumps(row) + "\n" for row in findings), encoding="utf-8")
            truth = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "unplanned finding status change"):
                validate_bundle(root, truth)


if __name__ == "__main__":
    unittest.main()
