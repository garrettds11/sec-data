"""Check source-aware CIM projections and their manifest."""

import json
import tempfile
import unittest
from pathlib import Path

from common.cim import project
from create_cim_events import export_cim, export_file


class CimProjectionTests(unittest.TestCase):
    def test_dns_units_and_reply(self):
        row = {"event_type": "dns", "timestamp": "2026-10-22T12:00:00Z",
               "client_ip": "10.0.0.1", "resolver_ip": "10.0.0.53", "query": "a.example",
               "query_type": "A", "answers": [], "rcode": "NXDOMAIN",
               "response_time_ms": 41, "event_id": "e1"}
        event = project("recon.jsonl", row)
        self.assertEqual(event["sec_data_cim_dataset"], "Network_Resolution.DNS")
        self.assertEqual(event["reply_code"], "Non-Existent Domain")
        self.assertEqual(event["response_time"], 0.041)
        self.assertEqual(event["answer_count"], 0)
        self.assertNotIn("tag", event)

    def test_vulnerability_cve_and_assessment_time(self):
        base = {"assessment_id": "synthetic-42-2026-10-22T11:59:00Z",
                "last_seen": "2026-01-01T00:00:00Z", "host_name": "host.example",
                "vulnerability_score_base": 4.0, "vulnerability_severity": "Info",
                "vulnerability_category": ["TLS"], "title": "Cipher issue",
                "scanner_plugin_id": "123", "vulnerability_id": "PLUGIN-123"}
        event = project("vulnerability.jsonl", base)
        self.assertEqual(event["time"], "2026-10-22T11:59:00Z")
        self.assertEqual(event["severity"], "informational")
        self.assertEqual(event["category"], "TLS")
        self.assertNotIn("cve", event)
        base["vulnerability_id"] = "CVE-2026-0001"
        self.assertEqual(project("vulnerability.jsonl", base)["cve"], "CVE-2026-0001")

    def test_firewall_action_and_bytes(self):
        row = {"time": "2026-10-22T12:00:00Z", "src_ip": "10.0.0.1",
               "dest_ip": "10.0.0.2", "action": "block", "bytes_in": 20, "bytes_out": 5}
        event = project("egress-firewall.jsonl", row)
        self.assertEqual((event["action"], event["bytes"]), ("blocked", 25))

    def test_bundle_manifest_counts_and_exclusions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            story = root / "story"
            story.mkdir()
            rows = [{"time": "2026-10-22T12:00:00Z", "event": "login",
                     "account": "LAB\\a", "outcome": "success", "server_name": "web"},
                    {"time": "2026-10-22T12:01:00Z", "event": "account_locked",
                     "account": "LAB\\a", "server_name": "web"}]
            (story / "web-auth.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
            (story / "compliance.jsonl").write_text("{}\n")
            result = export_cim(story, root / "cim")
            self.assertEqual((result["source_records"], result["cim_records"],
                              result["unmapped_records"]), (2, 1, 1))
            self.assertEqual(len((root / "cim" / "web-auth.cim.jsonl").read_text().splitlines()), 1)
            self.assertFalse((root / "cim" / "compliance.cim.jsonl").exists())
            with self.assertRaises(ValueError):
                export_file("web-auth.jsonl", story / "web-auth.jsonl", root / "cim" / "web-auth.cim.jsonl")


if __name__ == "__main__":
    unittest.main()
