import json
import random
import subprocess
import sys
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path

import create_compliance_table as compliance
import create_vuln_table as vuln
import upload_to_aws
from common.assets import DEFAULT_HOST_COUNT, MAX_HOST_COUNT, build_hosts
from common.export import export_records


class ScaleTests(unittest.TestCase):
    def test_inventory_scales_without_identity_or_address_collisions(self):
        default = build_hosts(random.Random(42))
        expanded = build_hosts(random.Random(42), 1024)
        self.assertEqual(expanded[:DEFAULT_HOST_COUNT], default)
        for field in ("fqdn", "ip", "mac"):
            self.assertEqual(len({h[field] for h in expanded}), len(expanded))
        self.assertTrue(all(ip_address(h["ip"]).is_private for h in expanded))
        self.assertTrue(all(h["ip"].split(".")[-1] not in ("0", "255") for h in expanded))
        with self.assertRaises(ValueError):
            build_hosts(random.Random(42), MAX_HOST_COUNT + 1)

    def test_vulnerability_stream_matches_list_and_limits(self):
        at = "2026-10-15T12:00:00Z"
        self.assertEqual(list(vuln.iter_items(42, at)), vuln.build_items(42, at))
        self.assertEqual(list(vuln.iter_items(42, at, 250)), list(vuln.iter_items(42, at, 250)))
        with self.assertRaisesRegex(ValueError, "only .* findings"):
            list(vuln.iter_items(42, at, findings_per_host=100))
        additions = vuln.load_additional_catalog(Path(vuln.__file__).parent /
                                                  "catalogs/vulnerability/illustrative.json")
        extended = vuln.build_items(42, at, catalog=vuln.CATALOG + additions)
        synthetic = [row for row in extended if row["vulnerability_id"].startswith("SYNTH-")]
        self.assertTrue(synthetic)
        self.assertTrue(all(row["synthetic"] and row["vulnerability_scanner_vendor"] == "Synthetic"
                            and row["vulnerability_reference"] == [] for row in synthetic))

    def test_export_exact_target_and_atomic_failure(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path = Path(tmp) / "records.jsonl"
            rows = ({"n": n} for n in range(5))
            self.assertEqual(export_records(path, rows, "jsonl", 3), 3)
            self.assertEqual([json.loads(line)["n"] for line in path.read_text().splitlines()], [0, 1, 2])
            with self.assertRaisesRegex(ValueError, "only 2"):
                export_records(path, ({"n": n} for n in range(2)), "jsonl", 3)
            self.assertEqual(len(path.read_text().splitlines()), 3)

    def test_compliance_snapshots_and_history_keys(self):
        one = compliance.build_items(42, "2026-10-15T12:00:00Z", host_count=250)
        two = compliance.build_items(42, "2026-10-22T12:00:00Z", host_count=250)
        self.assertEqual({x["host_name"] for x in one}, {x["host_name"] for x in two})
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path = Path(tmp) / "compliance.jsonl"
            export_records(path, iter(one), "jsonl")
            items = upload_to_aws.load_items(path, "compliance", history=True)
            self.assertEqual(len(items), len(one))
            self.assertTrue(all("@" in x["finding_id"] for x in items))
            self.assertEqual(upload_to_aws.validate_input(path, "compliance", history=True), len(one))

    def test_cli_snapshot_keys_and_status_transitions(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            for script, status_field in (("create_vuln_table.py", "vulnerability_status"),
                                         ("create_compliance_table.py", "compliance_status")):
                path = Path(tmp) / (script + ".jsonl")
                result = subprocess.run([sys.executable, str(Path(vuln.__file__).parent / script),
                                         "--seed", "42", "--snapshots", "2026-10-15T12:00:00Z",
                                         "2026-10-22T12:00:00Z", "--format", "jsonl",
                                         "--output", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual(len(rows), len({(r["host_name"], r["finding_id"]) for r in rows}))
                versions = {}
                for row in rows:
                    versions.setdefault((row["host_name"], row["base_finding_id"]), []).append(row[status_field])
                self.assertTrue(any(len(set(states)) > 1 for states in versions.values()), script)


if __name__ == "__main__":
    unittest.main()
