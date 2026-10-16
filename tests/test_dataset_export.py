import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

import create_compliance_table as compliance
import create_vuln_table as vuln
import upload_to_aws


class DatasetExportTests(unittest.TestCase):
    def test_compliance_json_round_trip(self):
        items = compliance.build_items(42)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compliance.json"
            path.write_text(json.dumps(items), encoding="utf-8")
            self.assertEqual(upload_to_aws.load_items(path, "compliance"), items)

    def test_vulnerability_decimal_score_round_trip(self):
        items = vuln.build_items(42)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.json"
            path.write_text(json.dumps(items, default=lambda v: float(v) if isinstance(v, Decimal) else str(v)), encoding="utf-8")
            restored = upload_to_aws.load_items(path, "vuln")
            self.assertEqual(len(restored), len(items))
            self.assertTrue(all(isinstance(x["vulnerability_score_base"], Decimal) for x in restored))

    def test_input_rejects_wrong_dataset_and_duplicate_keys(self):
        items = compliance.build_items(42)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dataset.json"
            path.write_text(json.dumps(items), encoding="utf-8")
            with self.assertRaises(ValueError):
                upload_to_aws.load_items(path, "vuln")
            path.write_text(json.dumps(items[:1] * 2), encoding="utf-8")
            with self.assertRaises(ValueError):
                upload_to_aws.load_items(path, "compliance")

    def test_table_definition(self):
        for dataset in ("vuln", "compliance"):
            definition = upload_to_aws.table_definition("test", dataset, "test")
            self.assertEqual(definition["BillingMode"], "PAY_PER_REQUEST")
            self.assertEqual(len(definition["GlobalSecondaryIndexes"]), 2)


if __name__ == "__main__":
    unittest.main()
