"""Readable output names, concurrent reservations, and CLI publication safety."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common.scenario import load_scenario
from create_dataset import reserve_run_directory, scenario_output_name

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / 'scenarios' / 'file-collection.json'


class RunDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "output").mkdir(exist_ok=True)

    def test_names_are_short_and_path_safe(self):
        self.assertEqual(scenario_output_name(load_scenario(SAMPLE)), 'file-collection')
        self.assertEqual(scenario_output_name(None), 'reference')
        self.assertEqual(scenario_output_name({'id': '../../My Story: V2'}), 'my-story-v2')
        self.assertEqual(scenario_output_name({'id': 'CON'}), 'scenario-con')
        self.assertEqual(scenario_output_name({'id': '///'}), 'scenario-unnamed')
        self.assertLessEqual(len(scenario_output_name({'id': 'a' * 200})), 48)
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as temp:
            path = Path(temp) / 'invalid.json'
            spec = load_scenario(SAMPLE)
            for invalid in ['../escape', 'CON', 'con', 'com1', '', 'two words', 'a' * 49, 5]:
                with self.subTest(invalid=invalid):
                    spec['output_name'] = invalid
                    path.write_text(json.dumps(spec), encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, 'output_name'):
                        load_scenario(path)

    def test_concurrent_reservations_skip_existing_paths_and_stale_locks(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as temp:
            root = Path(temp)
            (root / 'story-run001').write_text('keep', encoding='utf-8')
            (root / '.story-run002.reserved').mkdir()
            barrier = threading.Barrier(8)

            def reserve(_):
                with reserve_run_directory(root, 'story') as path:
                    barrier.wait(timeout=15)
                    self.assertFalse(path.exists())
                    path.mkdir()
                    return path.name

            with ThreadPoolExecutor(max_workers=8) as pool:
                names = list(pool.map(reserve, range(8)))
            self.assertEqual(set(names), {f'story-run{n:03d}' for n in range(3, 11)})
            self.assertEqual((root / 'story-run001').read_text(), 'keep')
            self.assertEqual([p.name for p in root.glob('.*.reserved')],
                             ['.story-run002.reserved'])

    def test_cli_defaults_overrides_failure_cleanup_and_repeatability(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as temp:
            root = Path(temp)
            command = [sys.executable, str(ROOT / 'create_dataset.py'),
                       '--scenario-file', str(SAMPLE), '--seed', '2',
                       '--start-time', '2024-11-12T08:00:00Z', '--duration-minutes', '120',
                       '--target-events', '100', '--json']
            outputs = []
            for number in (1, 2):
                result = subprocess.run(command, cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads(result.stdout)
                path = Path(summary['output_dir'])
                self.assertEqual(path, root / 'output' / f'file-collection-run{number:03d}')
                self.assertEqual(summary['event_records'], 100)
                outputs.append(path)
            first = {p.relative_to(outputs[0]): p.read_bytes()
                     for p in outputs[0].rglob('*') if p.is_file()}
            second = {p.relative_to(outputs[1]): p.read_bytes()
                      for p in outputs[1].rglob('*') if p.is_file()}
            self.assertEqual(first, second)
            override = root / 'explicit'
            result = subprocess.run(command + ['--output-dir', str(override)],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(json.loads(result.stdout)['output_dir']), override)
            again = subprocess.run(command + ['--output-dir', str(override)],
                                   cwd=root, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            bad = command.copy()
            bad[bad.index('--target-events') + 1] = '1'
            failed = subprocess.run(bad, cwd=root, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse((root / 'output' / 'file-collection-run003').exists())
            self.assertFalse(list((root / 'output').glob('.*.reserved')))
            custom = subprocess.run(command + ['--output-root', str(root / 'custom')],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(custom.returncode, 0, custom.stderr)
            self.assertEqual(Path(json.loads(custom.stdout)['output_dir']).parent, root / 'custom')
