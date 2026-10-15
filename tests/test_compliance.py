import random
import unittest

import create_vuln_table as vuln
import create_compliance_table as compliance
from common.assets import build_hosts


class ComplianceTests(unittest.TestCase):
    def test_shared_inventory(self):
        self.assertEqual(vuln.build_hosts(random.Random(42)), build_hosts(random.Random(42)))

    def test_repeatable(self):
        self.assertEqual(compliance.build_items(42), compliance.build_items(42))
        self.assertNotEqual(compliance.build_items(42), compliance.build_items(43))

    def test_keys_unique_and_evidence_consistent(self):
        items = compliance.build_items()
        self.assertTrue(items)
        self.assertEqual(len(items), len({(i["host_name"], i["finding_id"]) for i in items}))
        for i in items:
            self.assertIn(i["compliance_status"], ("pass", "fail"))
            self.assertEqual(i["compliance_status"] == "pass",
                             i["actual_value"] == i["expected_value"])
            self.assertTrue(i["synthetic"])

    def test_os_applicability(self):
        for i in compliance.build_items():
            self.assertTrue(
                (i["benchmark_id"] == "cis-ubuntu-2204" and i["host_os_full"] == "Ubuntu 22.04 LTS")
                or (i["benchmark_id"] == "cis-windows-server-2022"
                    and i["host_os_full"] == "Windows Server 2022")
            )

    def test_planted_when_applicable(self):
        for host, scenario in (("dc-01", "WIN-PASSWORD-LENGTH"),
                               ("bastion-01", "LIN-SSH-ROOT")):
            matches = [i for i in compliance.build_items()
                       if i["host_name"].startswith(host + ".") and i["control_id"] == scenario]
            if matches:
                self.assertEqual(matches[0]["compliance_status"], "fail")


if __name__ == "__main__":
    unittest.main()
