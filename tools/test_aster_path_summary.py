#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the deliberately small diagnostic Job Summary."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class SummaryTests(unittest.TestCase):
    def test_selected_bandwidth_is_labeled_and_allowlisted(self):
        import aster_path_summary as summary
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value, expected in [('', 'profile default'), ('0', 'no limit'), ('3', '3'), ('1000000', '1000000')]:
                self.assertIn('| Bandwidth per WAN egress (kbit/s) | ' + expected + ' |',
                              summary.render(root, {'BANDWIDTH_KBIT': value}))
            for value in ('SECRET', '3.5', '-1', '1000001'):
                self.assertNotIn('| Bandwidth per WAN egress', summary.render(root, {'BANDWIDTH_KBIT': value}))

    def test_summary_handles_failure_timeout_and_allowlists_evidence(self):
        path = Path(__file__).with_name('aster_path_summary.py')
        self.assertTrue(path.exists(), 'summary implementation is missing')
        spec = importlib.util.spec_from_file_location('summary', path)
        assert spec is not None and spec.loader is not None
        summary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(summary)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = summary.render(root, {'RUN_OUTCOME': 'failure'})
            self.assertIn('No receipt', text)
            (root / 'run-exit-code').write_text('124')
            self.assertIn('timeout', summary.render(root, {}))
            row = {'profile': 'baseline', 'status': 'fail', 'error': 'SECRET',
                   'accepted': {'node-a': {'id': {'payload': 'SECRET'}}},
                   'deliveries': {'node-a': {}}, 'samples': [
                       {'node-a': {'agent_pid': 3, 'monotonic': 1, 'rss_bytes': 1048576, 'cpu_ticks': 10, 'clock_ticks_per_second': 100}},
                       {'node-a': {'agent_pid': 3, 'monotonic': 3, 'rss_bytes': 2097152, 'cpu_ticks': 110, 'clock_ticks_per_second': 100}},
                       {'node-a': {'agent_pid': 4, 'monotonic': 4, 'rss_bytes': 1048576, 'cpu_ticks': 99999, 'clock_ticks_per_second': 100}}]}
            (root / 'baseline.json').write_text(json.dumps(row))
            text = summary.render(root, {'AGENTS': '<script>SECRET', 'PROFILE': 'baseline'})
            self.assertNotIn('SECRET', text)
            self.assertIn('| baseline | fail | node-a | 1 | 0 | — | 2.00 | 50.00 |', text)
            (root / 'receipt.json').write_text('{')
            self.assertIn('unreadable', summary.render(root, {}))
            (root / 'receipt.json').write_text(json.dumps({'status': 'pass', 'profiles': [dict(row, status='pass')]}))
            (root / 'run-exit-code').write_text('0')
            self.assertIn('| Campaign | pass |', summary.render(root, {}))


if __name__ == '__main__':
    unittest.main()
