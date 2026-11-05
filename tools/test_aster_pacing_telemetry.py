# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import aster_path_diagnostic as diagnostic


class TelemetryTests(unittest.TestCase):
    def test_bounded_pending_failed_spans_and_live_resources(self):
        self.assertTrue(hasattr(diagnostic, 'PacingTelemetry'), 'missing boundary telemetry')
        telemetry = diagnostic.PacingTelemetry()
        for _ in range(150):
            with telemetry.span('ipc', 'publish'):
                pass
        with self.assertRaises(ValueError):
            with telemetry.span('ipc', 'publication-ack'):
                current = telemetry.snapshot()
                self.assertEqual(current['active'][0]['operation'], 'ipc:publication-ack')
                self.assertGreaterEqual(current['active'][0]['age_seconds'], 0)
                raise ValueError('secret-token')
        result = telemetry.snapshot()
        self.assertEqual(len(result['operations']['ipc:publish']['recent_seconds']), 128)
        self.assertEqual(result['operations']['ipc:publish']['count'], 150)
        self.assertEqual(result['operations']['ipc:publication-ack']['errors'], 1)
        self.assertEqual(result['active'], [])
        self.assertNotIn('secret-token', json.dumps(result))
        for key in ('monotonic', 'finished_monotonic', 'affinity_count', 'cpu_count',
                    'host_cpu_stat', 'cpu_pressure', 'cgroup_cpu_stat', 'cgroup_cpu_max',
                    'worker_cpu_seconds'):
            self.assertIn(key, result['resources'])

    def test_pacing_failure_keeps_pending_operations_before_cleanup(self):
        import threading
        import time
        class Client:
            def call(self, *args):
                return {'deliveries': []}
            def publish_event(self, key, payload):
                release.wait(3)
                return {'id': key.decode()}
        release = threading.Event()
        telemetry = diagnostic.PacingTelemetry()
        with patch.object(diagnostic, 'TELEMETRY', telemetry):
            workload = diagnostic.Workload(Client(), 'sub', 'probe', 7, 1000, 1)
            try:
                deadline = time.monotonic() + 2
                while not workload.snapshot()['errors'] and time.monotonic() < deadline:
                    time.sleep(.01)
                failed = workload.snapshot()
                self.assertTrue(failed['errors'])
                self.assertIn('failure_telemetry', failed)
                self.assertEqual(sum(row['operation'] == 'publication:complete-lane-cycle'
                                     for row in failed['failure_telemetry']['active']), 6)
                release.set()
                workload.publisher.join(2)
                self.assertEqual(workload.snapshot()['failure_telemetry'], failed['failure_telemetry'])
                self.assertIn('pacing_telemetry', failed)
            finally:
                release.set()
                workload.close()

    def test_status_sample_brackets_slow_rpc_without_skewing_cpu_timestamp(self):
        import os
        pid = os.getpid()
        original = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/clab/state/agent.pid':
                return str(pid)
            return original(path, *args, **kwargs)
        class Client:
            def status(self):
                return {'ok': True}
        with patch.object(Path, 'read_text', read), \
                patch.object(diagnostic.time, 'monotonic', side_effect=[100, 101]):
            result = diagnostic.sample(Client())
        self.assertEqual(result['monotonic'], 100)
        self.assertEqual(result['status_finished_monotonic'], 101)

    def test_sdk_timings_are_bounded_whitelisted_and_kept_on_error(self):
        telemetry = diagnostic.PacingTelemetry()
        script = ('import json,sys\n'
                  'for line in sys.stdin:\n'
                  ' print(json.dumps({"error":"failed", "timing_seconds":'
                  '{"journal":0.125,"sdk-publish":0.5,"secret-token":2,"sdk-ack":-1}}),flush=True)\n')
        worker = diagnostic.PublicationWorker([sys.executable, '-u', '-c', script])
        try:
            with patch.object(diagnostic, 'TELEMETRY', telemetry):
                with self.assertRaisesRegex(ValueError, 'failed'):
                    worker.call('publish')
            result = telemetry.snapshot()
            self.assertEqual(result['operations']['sdk:journal']['wall_seconds'], .125)
            self.assertEqual(result['operations']['sdk:sdk-publish']['wall_seconds'], .5)
            self.assertNotIn('secret-token', json.dumps(result))
            self.assertNotIn('sdk:sdk-ack', result['operations'])
        finally:
            worker.close()

    def test_failed_publish_remains_counted_after_successful_recovery(self):
        telemetry = diagnostic.PacingTelemetry()
        identity = diagnostic.base64.b64encode(b'x' * 32).decode()
        responses = [
            {'error': 'failed', 'timing_seconds': {'journal': .1, 'sdk-publish': .2},
             'phase_outcomes': {'journal': 'success', 'sdk-publish': 'error'}},
            {'result': {'operations': [{'operationSequence': '1', 'state': 'committed',
                         'result': {'operationSequence': '1', 'receipt': {'eventId': identity}}}]},
             'timing_seconds': {'sdk-recover': .3},
             'phase_outcomes': {'sdk-recover': 'success'}},
            {'result': {'logicalKey': 'aw==', 'payload': 'cA=='},
             'timing_seconds': {'journal-show': .1}, 'phase_outcomes': {'journal-show': 'success'}},
            {'result': None, 'timing_seconds': {'sdk-ack': .1}, 'phase_outcomes': {'sdk-ack': 'success'}},
        ]
        script = ('import json,sys\nresponses=' + repr(responses) + '\n'
                  'for response,line in zip(responses,sys.stdin):\n'
                  ' print(json.dumps(response),flush=True)\n')
        worker = diagnostic.PublicationWorker([sys.executable, '-u', '-c', script])
        try:
            publisher = diagnostic.DiagnosticPublisher.__new__(diagnostic.DiagnosticPublisher)
            publisher._run = lambda action, *args, **kwargs: worker.call(action)
            with patch.object(diagnostic, 'TELEMETRY', telemetry):
                self.assertEqual(publisher.publish_event(b'k', b'p')['id'], identity)
            operations = telemetry.snapshot()['operations']
            self.assertEqual(operations['sdk:sdk-publish']['errors'], 1)
            self.assertEqual(operations['sdk:journal']['errors'], 0)
            self.assertEqual(operations['sdk:sdk-recover']['errors'], 0)
            self.assertEqual(operations['ipc-response:publish']['errors'], 1)
            self.assertEqual(operations['ipc-write:publish']['errors'], 0)
        finally:
            worker.close()

    def test_failed_recovery_counts_only_failed_phase(self):
        telemetry = diagnostic.PacingTelemetry()
        response = {'error': 'failed',
                    'timing_seconds': {'startup-recovery': .1, 'sdk-recover': .2},
                    'phase_outcomes': {'startup-recovery': 'success', 'sdk-recover': 'error'}}
        script = ('import json,sys\n'
                  'for line in sys.stdin:\n'
                  ' print(json.dumps(' + repr(response) + '),flush=True)\n')
        worker = diagnostic.PublicationWorker([sys.executable, '-u', '-c', script])
        try:
            with patch.object(diagnostic, 'TELEMETRY', telemetry):
                with self.assertRaisesRegex(ValueError, 'failed'):
                    worker.call('publication-recover')
            operations = telemetry.snapshot()['operations']
            self.assertEqual(operations['sdk:sdk-recover']['errors'], 1)
            self.assertEqual(operations['sdk:startup-recovery']['errors'], 0)
            self.assertEqual(operations['ipc-response:publication-recover']['errors'], 1)
        finally:
            worker.close()

    def test_persistent_protocol_separates_write_response_and_ack(self):
        self.assertTrue(hasattr(diagnostic, 'PacingTelemetry'))
        telemetry = diagnostic.PacingTelemetry()
        script = ('import json,sys,os\n'
                  'for line in sys.stdin:\n'
                  ' print(json.dumps({"result":{"pid":os.getpid()}}),flush=True)\n')
        worker = diagnostic.PublicationWorker([sys.executable, '-u', '-c', script])
        try:
            with patch.object(diagnostic, 'TELEMETRY', telemetry):
                first = worker.call('publish')
                second = worker.call('publication-ack')
            self.assertEqual(first['pid'], second['pid'])
            operations = telemetry.snapshot()['operations']
            for action in ('publish', 'publication-ack'):
                for phase in ('ipc-write', 'ipc-response'):
                    self.assertEqual(operations[phase + ':' + action]['count'], 1)
        finally:
            worker.close()


if __name__ == '__main__':
    unittest.main()
