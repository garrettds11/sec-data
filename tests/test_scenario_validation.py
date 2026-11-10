"""Authoring validation and the documented example-to-package workflow."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from common.identity import iter_identities
from common.scenario import (compile_scenario, load_scenario, merge_scenario_entities,
                             validate_scenario)
from common.world import iter_assets, iter_entities
from create_dataset import export_dataset

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "scenarios/file-collection.json"
CISA = ROOT / "scenarios/cisa/aa24-131a-black-basta.json"
START = datetime(2024, 11, 12, 8, tzinfo=timezone.utc)


class ScenarioValidationTests(unittest.TestCase):
    def setUp(self):
        self.assets = list(iter_assets(42, 23))
        self.entities = list(iter_entities())
        self.identities = list(iter_identities())

    def check_spec(self, spec, minutes=60):
        entities = merge_scenario_entities(spec, self.assets, self.entities)
        return validate_scenario(spec, minutes, self.assets, entities, self.identities)

    def test_tracked_examples_validate_and_compile_to_the_reported_count(self):
        for path in (ROOT / "scenarios").rglob("*.json"):
            with self.subTest(path=path):
                spec = load_scenario(path)
                result = self.check_spec(spec, 120)
                events, truth = compile_scenario(
                    spec, START, 120, self.assets,
                    merge_scenario_entities(spec, self.assets, self.entities),
                    self.identities, "test-authoring")
                self.assertEqual(result["prescribed_observations"], len(events))
                self.assertEqual(result["steps"], len(truth))

    def test_validator_and_compiler_reject_the_same_bad_observations(self):
        base = load_scenario(EXAMPLE)
        cases = []
        for field, value in (("unsupported_field", "x"), ("malicious", "yes"),
                             ("dest", {"ref": "asset:no-such-host:ip"}),
                             ("bytes", 1)):
            spec = copy.deepcopy(base)
            spec["steps"][0]["observations"][0]["fields"][field] = value
            cases.append(spec)
        for offset in (float("nan"), 3600):
            spec = copy.deepcopy(base)
            spec["steps"][0]["offset_seconds"] = offset
            cases.append(spec)
        spec = copy.deepcopy(base)
        spec["steps"][0]["depends_on"] = ["not-an-earlier-step"]
        cases.append(spec)
        for spec in cases:
            with self.subTest(spec=spec):
                entities = merge_scenario_entities(spec, self.assets, self.entities)
                messages = []
                for operation in (
                        lambda: validate_scenario(spec, 60, self.assets, entities, self.identities),
                        lambda: compile_scenario(spec, START, 60, self.assets, entities, self.identities, "test")):
                    with self.assertRaises(ValueError) as caught:
                        operation()
                    messages.append(str(caught.exception))
                self.assertEqual(*messages)

    def test_minimum_duration_includes_observation_delay(self):
        spec = load_scenario(EXAMPLE)
        spec["steps"] = spec["steps"][:1]
        spec["steps"][0]["offset_seconds"] = 59
        spec["steps"][0]["observations"][0]["delay_ms"] = 1000
        self.assertEqual(self.check_spec(spec)["minimum_duration_minutes"], 2)
        with self.assertRaisesRegex(ValueError, "delay_ms"):
            self.check_spec(spec, 1)

    def test_custom_entity_authorization_and_collisions(self):
        spec = load_scenario(EXAMPLE)
        for authorized in (False, True):
            spec["entities"][0]["authorized"] = authorized
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "scenario.json"
                path.write_text(json.dumps(spec), encoding="utf-8")
                self.check_spec(load_scenario(path))
        spec["entities"][0]["ip"] = self.assets[0]["ip"]
        with self.assertRaisesRegex(ValueError, "IP conflicts"):
            self.check_spec(spec)

    def test_cli_is_read_only_and_rejects_too_small_target(self):
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, str(ROOT / "validate_scenario.py"),
                       "--scenario-file", str(CISA), "--duration-minutes", "120"]
            result = subprocess.run(command, cwd=temp, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["dataset_generated"])
            self.assertEqual(report["prescribed_observations"], 43)
            self.assertEqual(report["minimum_duration_minutes"], 111)
            self.assertEqual(list(Path(temp).iterdir()), [])
            bad = subprocess.run(command + ["--target-events", "42"], cwd=temp,
                                 text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("at least 43", bad.stderr)
            for mode, key in (("--describe-contract", "source_datasets"),
                              ("--describe-context", "assets")):
                result = subprocess.run([sys.executable, str(ROOT / "validate_scenario.py"), mode],
                                        cwd=temp, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(key, json.loads(result.stdout))
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_cisa_example_publishes_reconciled_package_without_truth_leaks(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "package"
            manifest = export_dataset(42, START, 120, 1, 23, target,
                                      target_events=10000, scenario_file=CISA)
            self.assertEqual(manifest["event_records"], 10000)
            self.assertEqual(manifest["planted_records"], 43)
            self.assertEqual(manifest["background_records"], 9957)
            events = [json.loads(line) for path in (target / "events").glob("*.jsonl")
                      for line in path.read_text().splitlines()]
            self.assertEqual(len(events), 10000)
            self.assertFalse(any("DOCUMENTED:" in json.dumps(row) or "FICTIONAL:" in json.dumps(row)
                                 for row in events))
            truth = json.loads((target / "truth/scenario-truth.json").read_text())
            self.assertEqual(len(truth["steps"]), 23)
            planted_ids = {eid for step in truth["steps"] for eid in step["event_ids"]}
            self.assertEqual(sum(row["event_id"] in planted_ids for row in events), 43)


if __name__ == "__main__":
    unittest.main()
