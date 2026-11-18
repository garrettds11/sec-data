import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from common.ioc_coverage import check_coverage, check_dataset, load_coverage
from common.scenario import _validate_fields
from create_dataset import export_dataset

ROOT = Path(__file__).resolve().parents[1]
V2 = ROOT / "scenarios/cisa/aa24-131a-black-basta-v2.json"
CATALOG = ROOT / "catalogs/intelligence/aa24-131a-publication-coverage-v2.json"
START = datetime(2024, 11, 12, 8, tzinfo=timezone.utc)


class IocCoverageTests(unittest.TestCase):
    def test_hash_contract_accepts_real_digests_only_on_the_correct_dataset(self):
        for field, dataset in (("file_hash", "Endpoint.Filesystem"),
                               ("process_hash", "Endpoint.Processes")):
            for length in (32, 40, 64, 128):
                _validate_fields({field: "a" * length}, dataset)
            for bad in ("a" * 63, "z" * 64, "SHA256=" + "a" * 64):
                with self.assertRaisesRegex(ValueError, field):
                    _validate_fields({field: bad}, dataset)
            with self.assertRaisesRegex(ValueError, field):
                _validate_fields({field: "a" * 64}, "Web.Web")

    def test_catalog_keeps_all_original_table_rows_and_normalization_evidence(self):
        c = load_coverage(CATALOG)
        self.assertEqual({k: len(v) for k, v in c["source_tables"].items()},
                         {"7": 44, "8": 45, "9": 33, "10": 47, "11": 46})
        self.assertEqual(len(c["indicators"]), 261)
        for table, rows in c["source_tables"].items():
            for row in range(1, len(rows) + 1):
                self.assertTrue(any(e["source"] == "may-2024" and e["table"] == int(table)
                                    and e["row"] == row for e in c["indicators"]), (table, row))
        values = {e["value"] for e in c["indicators"]}
        self.assertIn("0112e3b20872760dda5f658f6b546c85f126e803e27f0577b294f335ffa5a298", values)
        self.assertIn("trailshop.net", values)
        self.assertIn("realbumblebee.net", values)
        self.assertIn("66.249.66.18", values)
        self.assertIn("C:\\Users\\Public\\Audio\\Jun.exe", values)

    def test_missing_query_is_not_satisfied_by_a_narrative_or_unrelated_field(self):
        c = {"scenario_id": "test", "indicators": [
            {"id": "dns", "source": "s", "kind": "domain", "value": "example.org",
             "field": "query", "match": "exact", "step_id": "x"}]}
        for event in ({"description": "example.org"}, {"query": "notexample.org"},
                      {"dest": "example.org"}):
            self.assertEqual(check_coverage(c, [event])["missing"], 1)
        self.assertEqual(check_coverage(c, [{"query": "EXAMPLE.ORG", "event_id": "e"}])["missing"], 0)

    def test_v2_exports_all_promised_values_with_evidence_and_no_truth_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dataset"
            manifest = export_dataset(2, START, 120, 1, 23, out, 10000, V2)
            self.assertEqual((manifest["planted_records"], manifest["background_records"]), (280, 9720))
            report = check_dataset(out, CATALOG)
            self.assertEqual((report["present"], report["missing"]), (261, 0))
            self.assertTrue(all(r["event_ids"] for r in report["assertions"]))
            events = [json.loads(line) for p in (out / "events").glob("*.jsonl")
                      for line in p.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 10000)
            self.assertTrue(all("2024-11-12T08:00:00.000Z" <= r["time"] < "2024-11-12T10:00:00.000Z" for r in events))
            self.assertFalse(any("DOCUMENTED:" in json.dumps(r) or "FICTIONAL" in json.dumps(r)
                                 or "step_id" in r for r in events))
            for r in events:
                if r.get("file_hash") in {"96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be",
                                          "1c1b2d7f790750d60a14bd661dae5c5565f00c6ca7d03d062adcecda807e1779",
                                          "360c9c8f0a62010d455f35588ef27817ad35c715a5f291e43449ce6cb1986b98"}:
                    self.assertEqual(r["sec_data_source"], "endpoint-lab.jsonl")
                    self.assertIn("prod-app-01", r["dest"])
            # Mutating analyst events must fail even though context/truth remain intact.
            for p in (out / "events").glob("*.jsonl"):
                rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
                rows = [r for r in rows if r.get("query") != "trailshop.net"]
                p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            self.assertGreater(check_dataset(out, CATALOG)["missing"], 0)
            cli = subprocess.run([sys.executable, str(ROOT / "validate_ioc_coverage.py"),
                                  "--dataset-dir", str(out), "--coverage-file", str(CATALOG)],
                                 capture_output=True, text=True)
            self.assertEqual(cli.returncode, 1, cli.stderr)
            self.assertEqual(json.loads(cli.stdout)["status"], "incomplete")

    def test_source_and_catalog_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dataset-manifest.json").write_text(json.dumps({"scenario_id": "other"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "scenario_id"):
                check_dataset(root, CATALOG)


if __name__ == "__main__":
    unittest.main()
