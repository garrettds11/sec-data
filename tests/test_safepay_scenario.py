"""Source-backed SafePay compilation and indicator reconciliation, without export."""
import collections
import copy
import hashlib
import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from common.identity import iter_identities
from common.ioc_coverage import check_coverage, load_coverage
from common.scenario import _validate_fields, compile_scenario, load_scenario, validate_scenario
from common.world import iter_assets, iter_entities

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / 'scenarios/cisa/aa26-293a-safepay-v1.json'
CATALOG = ROOT / 'catalogs/intelligence/aa26-293a-safepay-coverage-v1.json'
SOURCE = ROOT / 'catalogs/intelligence/sources/AA26-293A-stix.json'


class SafePayScenarioTests(unittest.TestCase):
    def test_uploaded_source_inventory_and_every_stix_value_are_preserved(self):
        raw = SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '73cbd07da8d74a322aa0c76a08933c8731045590e8abdee3409639f7ef40f5d0')
        stix, cat = json.loads(raw), load_coverage(CATALOG)
        self.assertEqual(cat['source_file']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(stix['objects']), 63)
        indicators = [o for o in stix['objects'] if o['type'] == 'indicator']
        self.assertEqual(len(indicators), 19)
        inventory = {o['object_id']: o for o in cat['stix_indicators']}
        self.assertEqual(set(inventory), {o['id'] for o in indicators})
        expected = []
        for obj in indicators:
            self.assertEqual(inventory[obj['id']]['pattern'], obj['pattern'])
            terms = re.findall(r"(?:ipv4-addr:value|file:hashes\.(?:'[^']+'|\w+)) = '([^']+)'",
                               obj['pattern'])
            self.assertEqual(terms, [e['value'] for e in inventory[obj['id']]['assertions']])
            expected.extend(terms)
        actual = [e['value'] for e in cat['indicators'] if e['source'] == 'uploaded-stix']
        self.assertEqual(collections.Counter(actual), collections.Counter(expected))
        self.assertEqual(len(actual), 22)
        self.assertEqual(collections.Counter(e['kind'] for e in cat['indicators']),
                         {'ipv4': 9, 'sha1': 5, 'sha256': 6, 'md5': 1, 'ssdeep': 1,
                          'path': 36, 'hostname': 4})
        alternatives = [o for o in inventory.values() if o['operator'] == 'OR']
        self.assertEqual(len(alternatives), 1)
        self.assertEqual(len(alternatives[0]['assertions']), 4)
        self.assertEqual(len(cat['publication']['file_rows']), 30)

    def test_compiled_evidence_covers_values_and_missing_evidence_fails(self):
        spec, cat = load_scenario(SCENARIO), load_coverage(CATALOG)
        assets, entities, identities = list(iter_assets(2, 23)), list(iter_entities()), list(iter_identities())
        result = validate_scenario(spec, 120, assets, entities, identities)
        self.assertEqual(result['steps'], 14)
        self.assertEqual(result['prescribed_observations'], 85)
        self.assertEqual(result['minimum_duration_minutes'], 84)
        events, truth = compile_scenario(spec, datetime(2026, 10, 21, 8, tzinfo=timezone.utc),
                                         120, assets, entities, identities, 'test-safepay')
        report = check_coverage(cat, events)
        self.assertEqual((report['present'], report['missing']), (62, 0))
        self.assertEqual(len(events), 85)
        self.assertEqual(len(truth), 14)
        self.assertTrue(all('2026-10-21T08:' <= e['time'] < '2026-10-21T10:' for e in events))
        self.assertFalse(any('scenario_id' in e or 'step_id' in e for e in events))
        # Isolate the STIX-only SharpShares SHA-1: narrative or another hash cannot fill the gap.
        wanted = 'C13BC01D6630D6E51F5DC3D3B0D90D8D499FF240'
        changed = [e for e in events if e.get('file_hash') != wanted]
        missing = check_coverage(cat, changed)
        self.assertEqual(missing['missing'], 1)
        self.assertEqual(next(e for e in missing['assertions'] if e['value'] == wanted)['status'], 'missing')
        ssdeep_event = next(e for e in events if 'file_hash_ssdeep' in e)
        changed = copy.deepcopy(events)
        next(e for e in changed if 'file_hash_ssdeep' in e)['file_hash_ssdeep'] = ssdeep_event['file_hash_ssdeep'].swapcase()
        self.assertEqual(check_coverage(cat, changed)['missing'], 1)

    def test_ssdeep_is_typed_filesystem_metadata_not_arbitrary_hex_or_similarity(self):
        value = '384:px+JDZS7LRJyibXRmymaahSmCS8HVcS8C6YK6P+H+0Np0FO:pxeiJK4HDKZ32O'
        _validate_fields({'file_hash_ssdeep': value}, 'Endpoint.Filesystem')
        for dataset, bad in [('Web.Web', value), ('Endpoint.Processes', value),
                             ('Endpoint.Filesystem', 'bad hash'), ('Endpoint.Filesystem', '0:a:b')]:
            with self.subTest(dataset=dataset, bad=bad):
                with self.assertRaisesRegex(ValueError, 'file_hash_ssdeep'):
                    _validate_fields({'file_hash_ssdeep': bad}, dataset)
