"""Gunra STIX completeness and same-event compound indicator semantics."""
import collections
import copy
import hashlib
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common.identity import iter_identities
from common.ioc_coverage import check_coverage, load_coverage
from common.scenario import _validate_fields, compile_scenario, load_scenario, validate_scenario
from common.world import iter_assets, iter_entities

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / 'scenarios/cisa/aa26-222a-gunra-v1.json'
CATALOG = ROOT / 'catalogs/intelligence/aa26-222a-gunra-coverage-v1.json'
SOURCE = ROOT / 'catalogs/intelligence/sources/AA26-222A-stix.json'
START = datetime(2026, 8, 11, tzinfo=timezone.utc)


class GunraScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "output").mkdir(exist_ok=True)

    def setUp(self):
        self.spec = load_scenario(SCENARIO)
        self.catalog = load_coverage(CATALOG)
        self.assets, self.entities, self.identities = list(iter_assets(2, 23)), list(iter_entities()), list(iter_identities())

    def compiled(self):
        return compile_scenario(self.spec, START, 120, self.assets, self.entities,
                                self.identities, 'test-gunra')[0]

    def test_source_bytes_and_every_pattern_term_are_accounted_for(self):
        raw = SOURCE.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(digest, 'b699465192e59d8cbd15ffe9da0b7997118c16c881f42ddcd2dbe5941d1eaede')
        self.assertEqual(self.catalog['source_file']['sha256'], digest)
        stix = json.loads(raw)
        self.assertEqual(len(stix['objects']), 80)
        source = {o['id']: o for o in stix['objects'] if o['type'] == 'indicator'}
        self.assertEqual(len(source), 29)
        mapped = {o['id']: o for o in self.catalog['stix_indicators']}
        self.assertEqual(set(source), set(mapped))
        terms = []
        for id, obj in source.items():
            self.assertEqual(obj['pattern'], mapped[id]['pattern'])
            values = re.findall(r"(?:ipv4-addr:value|domain-name:value|email-addr:value|file:name|file:hashes\.(?:'[^']+'|\w+)) = '([^']+)'", obj['pattern'])
            self.assertEqual(collections.Counter(values), collections.Counter(t['value'] for t in mapped[id]['terms']))
            terms.extend(values)
        assertions = [e for e in self.catalog['indicators'] if e['source'] == 'uploaded-stix']
        self.assertEqual(collections.Counter(terms), collections.Counter(e['value'] for e in assertions))
        self.assertEqual(len(assertions), 35)
        self.assertEqual(len(self.catalog['indicators']), 45)
        guarded = [e for e in assertions if 'conditions' in e]
        self.assertEqual(len(guarded), 6)
        msmp = [e for e in guarded if e['conditions'][0]['value'] == 'msmp.exe']
        self.assertEqual({e['kind'] for e in msmp}, {'sha1', 'sha256', 'md5'})

    def test_compilation_covers_every_value_without_fake_dns_or_email_transport(self):
        result = validate_scenario(self.spec, 120, self.assets, self.entities, self.identities)
        self.assertEqual((result['steps'], result['prescribed_observations'], result['minimum_duration_minutes']), (15, 60, 91))
        events = self.compiled()
        report = check_coverage(self.catalog, events)
        self.assertEqual((report['present'], report['missing'], report['unique_indicators']), (45, 0, 44))
        self.assertEqual(len(events), 60)
        self.assertTrue(all(START <= datetime.fromisoformat(e['time'].replace('Z', '+00:00')) < START + timedelta(minutes=120) for e in events))
        self.assertFalse(any(e.get('query', '').endswith('.onion') for e in events))
        for event in events:
            if any(k in event for k in ['file_domain', 'file_email', 'file_contact_id', 'file_account']):
                self.assertEqual(event['sec_data_source'], 'endpoint-lab.jsonl')
                self.assertEqual(event['sec_data_cim_dataset'], 'Endpoint.Filesystem')
        self.assertTrue(any('S' in v for v in self.catalog['publication']['qtox_raw']))

    def test_hash_and_filename_must_match_one_observation(self):
        events = copy.deepcopy(self.compiled())
        entry = next(e for e in self.catalog['indicators'] if e.get('conditions', [{}])[0].get('value') == 'cryptor.exe')
        sample = next(e for e in events if e.get('file_hash') == entry['value'])
        correct_name_only = {k: v for k, v in sample.items() if k != 'file_hash'}
        correct_name_only['event_id'] = 'separate-file-evidence'
        sample['file_path'] = r'C:\Lab\Samples\unrelated.exe'
        events.append(correct_name_only)
        report = check_coverage(self.catalog, events)
        assertion = next(a for a in report['assertions'] if a['id'] == entry['id'])
        self.assertEqual(assertion['status'], 'missing')
        self.assertEqual(assertion['conditions'], entry['conditions'])
        self.assertEqual(report['missing'], 1)

    def test_artifact_fields_are_typed_and_not_native_sysmon_or_other_datasets(self):
        for name, value in [('file_email', 'test@example.net'), ('file_domain', 'sample.onion'),
                            ('file_contact_id', 'SOURCE123S'), ('file_account', 'forticloud-sync')]:
            _validate_fields({name: value}, 'Endpoint.Filesystem')
            with self.assertRaisesRegex(ValueError, name):
                _validate_fields({name: value}, 'Authentication.Authentication')
        with self.assertRaisesRegex(ValueError, 'file_email'):
            _validate_fields({'file_email': 'not an email'}, 'Endpoint.Filesystem')
        spec = copy.deepcopy(self.spec)
        artifact = next(o for s in spec['steps'] for o in s['observations'] if 'file_email' in o['fields'])
        artifact['source'] = 'sysmon.jsonl'
        with self.assertRaisesRegex(ValueError, 'endpoint-lab'):
            validate_scenario(spec, 120, self.assets, self.entities, self.identities)
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as temp:
            path = Path(temp) / 'coverage.json'
            for bad in [[], None, 'not a list', [{'kind': 'email', 'field': 'dest', 'value': 'a@b.c', 'match': 'exact'}]]:
                catalog = copy.deepcopy(self.catalog)
                catalog['indicators'][0]['conditions'] = bad
                path.write_text(json.dumps(catalog))
                with self.assertRaisesRegex(ValueError, 'conditions'):
                    load_coverage(path)
