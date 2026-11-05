#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
import unittest
import aster_benchmark as benchmark


class StatisticsTests(unittest.TestCase):
    def test_final_snapshot_updates_delivery_and_expected_before_accounting(self):
        import ast
        import inspect
        import aster_path_diagnostic as diagnostic
        from types import SimpleNamespace
        # Execute the controller's actual finalization block with deterministic
        # worker snapshots, avoiding Docker and wall-clock scheduling.
        tree = ast.parse(inspect.getsource(diagnostic))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_profile')
        body = next(n.body for n in function.body if isinstance(n, ast.Try))
        start = next(i for i, n in enumerate(body) if isinstance(n, ast.Assign)
                     and ast.unparse(n.targets[0]) == "report['restore_delivery_seconds']")
        end = next(i for i in range(start, len(body)) if isinstance(body[i], ast.Expr)
                   and ast.unparse(body[i]) == "configure('outage')")
        code = compile(ast.Module(body=body[start:end], type_ignores=[]), '<controller-finalize>', 'exec')
        event = lambda identity: {'id': identity, 'logicalKey': identity, 'payload': 'p'}
        report = {'accepted': {'node-a': {'a': event('a')}},
                  'deliveries': {'node-a': {}}, 'delivery_times': {'node-a': {}}}
        def consume(action):
            self.assertEqual(action, 'end-workload')
            report['accepted']['node-a']['b'] = event('b')
            report['accepted']['node-a']['c'] = event('c')
            report['deliveries']['node-a'].update(a=event('a'), b=event('b'))
            report['delivery_times']['node-a'].update(a=12, b=14)
        namespace = dict(report=report, restored=None, benchmark=True, deadline=13,
            time=SimpleNamespace(monotonic=lambda: 20), sample_all=lambda: None,
            interfaces=[], phase=lambda _: None, consume=consume, workers={},
            delivery_observation=diagnostic.delivery_observation)
        exec(code, namespace)
        self.assertEqual(report['delivery_counts']['node-a'], {'unique': 1, 'missing': 2})

    def test_delivery_observation_uses_absolute_cutoff_and_checks_content(self):
        import aster_path_diagnostic as diagnostic
        expected = {'a': {'id': 'a', 'logicalKey': 'k', 'payload': 'p'}, 'b': {'id': 'b', 'logicalKey': 'k', 'payload': 'p'}}
        actual = dict(expected)
        self.assertEqual(diagnostic.delivery_observation(expected, actual, {'a': 12, 'b': 14}, 13), {'unique': 1, 'missing': 1})
        with self.assertRaises(ValueError):
            diagnostic.delivery_observation(expected, {'a': dict(expected['a'], payload='bad')}, {'a': 12}, 13)

    def test_interval_is_half_open_and_late_results_are_separate(self):
        stats = benchmark.PublicationStatistics(10, 2)
        stats.attempt('a', 10)
        stats.attempt('b', 11)
        stats.attempt('c', 11.5)
        stats.complete('a', 'accepted', 11)
        stats.complete('b', 'accepted', 12)
        stats.complete('a', 'accepted', 13)  # replay is idempotent
        row = stats.summary()
        self.assertEqual(row['accepted_during'], 1)
        self.assertEqual(row['accepted_later'], 1)
        self.assertEqual(row['unknown'], 1)
        self.assertEqual(row['actual_events_per_second'], .5)
        self.assertEqual(row['latency_seconds'], {'count': 2, 'median': 1, 'p95': 1, 'max': 1})
        with self.assertRaises(ValueError):
            stats.attempt('late', 12)


class ReportTests(unittest.TestCase):
    def test_structured_error_is_visible_without_exception_secrets(self):
        source = {'status': 'fail', 'error': 'token=super-secret', 'error_kind': 'TimeoutError',
                  'error_stage': 'drain', 'error_reason': 'deadline-exceeded'}
        public = benchmark.public_report(source)
        self.assertEqual(public.get('error_stage'), 'drain')
        self.assertEqual(public.get('error_reason'), 'deadline-exceeded')
        html = benchmark.render_html(public)
        self.assertIn('drain', html)
        self.assertIn('deadline-exceeded', html)
        self.assertNotIn('super-secret', html)
        campaign = benchmark.render_html(dict(source, profiles=[]))
        self.assertIn('deadline-exceeded', campaign)
        self.assertEqual(benchmark.public_report({k: v for k, v in source.items()
                         if k != 'error_reason'})['error_reason'], 'deadline-exceeded')
        for key in ('error_stage', 'error_reason'):
            unsafe = benchmark.public_report(dict(source, **{key: 'super-secret'}))
            self.assertNotIn('super-secret', str(unsafe))


    def test_report_is_allowlisted_offline_and_escapes_labels(self):
        report = {'status': 'completed', 'error': 'secret-token', 'profiles': [{
            'profile': 'baseline', 'status': 'completed', 'measurement': {'start_monotonic': 10, 'duration_seconds': 2},
            'accepted': {'node-a': {'secret': {'payload': 'secret-payload'}}},
            'benchmark': {'node-a': {'attempts': 2, 'accepted_during': 1, 'accepted_later': 1,
                'rejected': 0, 'unknown': 0, 'actual_events_per_second': .5,
                'latency_seconds': {'count': 2, 'median': 1, 'p95': 1, 'max': 1}, 'token': 'secret-token'}},
            'benchmark_resources': {'node-a': [{'monotonic': 10, 'accepted': 0, 'delivered': 0,
                'processes': {'agent': {'pid': 2, 'start_ticks': 1, 'monotonic': 10, 'cpu_seconds': 1,
                'rss_bytes': 4096, 'cpu_percent': None, 'token': 'secret-token'}}}]}}]}
        public = benchmark.public_report(report)
        import json
        self.assertNotIn('secret', json.dumps(public))
        html = benchmark.render_html(public, title='<img src=x onerror=bad>')
        self.assertIn('&lt;img', html)
        self.assertNotIn('<img', html)
        self.assertNotIn('https:', html)
        self.assertNotIn('secret', html)
        self.assertIn('Accepted during', html)
        self.assertIn('polyline', html)


class StreamDeadlineTests(unittest.TestCase):
    def test_buffered_response_observed_after_cutoff_remains_unresolved(self):
        import aster_path_diagnostic as diagnostic
        from pathlib import Path
        from unittest.mock import patch
        for expired_before_read in (False, True):
            with self.subTest(expired_before_read=expired_before_read):
                now = [10.0]
                applied, sent, reads = [], [], []
                class Session:
                    def call(self, *args, **kwargs):
                        return {'ready': True}
                    def send(self, action, **kwargs):
                        sent.append(action)
                        if action == 'stream-item':
                            self.intent = kwargs['intent']
                        if action == 'stream-finish' and expired_before_read:
                            now[0] = 13.1
                    def read(self, **kwargs):
                        reads.append(kwargs)
                        now[0] = 13.1
                        if len(reads) > 1:
                            return {'finished': True, 'max_schedule_lag_seconds': 0}
                        return {'intent': self.intent, 'publication': {'operationSequence': 1,
                            'receipt': {'eventId': diagnostic.base64.b64encode(b'e' * 32).decode()}}}
                    def close(self):
                        pass
                publisher = diagnostic.DiagnosticPublisher(Path('unused'), Path('unused'), 'client')
                publisher.session = Session()
                stats = benchmark.PublicationStatistics(10, 2)
                with patch.object(diagnostic.time, 'monotonic', side_effect=lambda: now[0]):
                    publisher.publish_stream([(b'k', b'p')], 1, 10, applied.append,
                                             duration=2, settle_seconds=1, statistics=stats)
                self.assertEqual(applied, [])
                self.assertEqual(stats.summary()['unknown'], 1)
                self.assertEqual(stats.summary()['responses'], [])
                self.assertNotIn('stream-applied', sent)
                self.assertEqual(len(reads), 0 if expired_before_read else 1)
                self.assertIsNone(publisher.session)

    def test_settlement_timeout_counts_unknown_without_republishing(self):
        import aster_path_diagnostic as diagnostic
        from pathlib import Path
        from unittest.mock import patch
        now = [10.0]
        class Session:
            def call(self, *args, **kwargs):
                return {'ready': True}
            def send(self, *args, **kwargs):
                pass
            def read(self, **kwargs):
                now[0] = 13.0
                raise TimeoutError('publication IPC deadline')
            def close(self):
                pass
        publisher = diagnostic.DiagnosticPublisher(Path('unused'), Path('unused'), 'client')
        publisher.session = Session()
        stats = benchmark.PublicationStatistics(10, 2)
        with patch.object(diagnostic.time, 'monotonic', side_effect=lambda: now[0]):
            publisher.publish_stream([(b'k', b'p')], 1, 10, lambda _: None,
                                     duration=2, settle_seconds=1, statistics=stats)
        self.assertEqual(stats.summary()['unknown'], 1)
        self.assertIsNone(publisher.session)


class DurationInputTests(unittest.TestCase):
    def test_duration_default_and_max_rate_leave_count_mode_explicit(self):
        import aster_path_diagnostic as diagnostic
        args = ['--output', 'unused', '--profiles', 'baseline']
        config = diagnostic.parse_config(args + ['--duration-seconds', '2', '--events-per-second', 'max'])
        self.assertTrue(config.benchmark)
        self.assertEqual(config.events_per_second, 0)
        config = diagnostic.parse_config(args + ['--events-per-agent', '20'])
        self.assertFalse(config.benchmark)


class ResourceTests(unittest.TestCase):
    def test_cpu_uses_actual_elapsed_and_never_crosses_process_lifetime(self):
        a = {'monotonic': 10, 'pid': 2, 'start_ticks': 5, 'cpu_seconds': 1, 'rss_bytes': 4096}
        b = dict(a, monotonic=12, cpu_seconds=2)
        self.assertEqual(benchmark.cpu_percent(a, b), 50)
        for changed in ({'pid': 3}, {'start_ticks': 6}, {'cpu_seconds': .5}, {'monotonic': 10}):
            self.assertIsNone(benchmark.cpu_percent(a, dict(b, **changed)))
        self.assertIsNone(benchmark.cpu_percent(None, b))

    def test_quantiles_cover_every_sample_and_empty_is_unavailable(self):
        self.assertEqual(benchmark.quantiles(range(1, 101)), {'count': 100, 'median': 50.5, 'p95': 95, 'max': 100})
        self.assertIsNone(benchmark.quantiles([])['median'])


if __name__ == '__main__':
    unittest.main()
