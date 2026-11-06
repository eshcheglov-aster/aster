import unittest
from report import summarize, coordinates

class ReportTests(unittest.TestCase):
    def test_per_agent_offered_count_and_rate_denominators(self):
        result = summarize(dict(duration_seconds=60, rate=10, publisher_nodes=5,
                                rate_scope='per_agent', measurements=dict(attempts=[], accepted={}, delivered=[{}]*5)))
        self.assertEqual(result['not_generated'], 3000)
        self.assertEqual(result['offered_total_rate'], 50)
        self.assertEqual(result['offered_per_agent_rate'], 10)

    def test_half_open_window_pending_empty_and_late(self):
        source = dict(duration_seconds=2, measurements=dict(
            attempts=[dict(outcome='accepted', response_s=t, send_started_s=0) for t in [0, 1.99, 2.0]] + [dict(outcome='unresolved'), dict(outcome='rejected'), dict(outcome='unsent')],
            accepted={'a': 1, 'b': 2}, delivered=[{'a': 1, 'b': 4}, {'a': 1}], errors=[]))
        source['rate'] = 10
        result = summarize(source)
        self.assertEqual(result['not_generated'], 14)
        self.assertEqual(result['accepted_within'], 2)
        self.assertEqual(result['accepted_after'], 1)
        self.assertEqual(result['eps'], [1, 1])
        self.assertEqual(result['unresolved'], 1)
        self.assertEqual(result['unsent'], 1)
        self.assertEqual(result['delivery'][0]['completion_after_publication_s'], 2)
        self.assertIsNone(result['delivery'][1]['completion_after_publication_s'])
        self.assertEqual(result['delivery'][1]['pending'], 1)
        empty = summarize(dict(duration_seconds=2, measurements=dict(attempts=[], accepted={}, delivered=[{}])))
        self.assertIsNone(empty['latency_median_s'])
        self.assertIsNone(empty['delivery'][0]['completion_after_publication_s'])
    def test_delivery_latency_uses_send_start_not_response(self):
        source = dict(duration_seconds=2, measurements=dict(
            attempts=[dict(sequence=1, event_id='a', outcome='accepted', response_s=1.5, send_started_s=.25),
                      dict(sequence=2, event_id='b', outcome='accepted', response_s=2.5, send_started_s=1)],
            accepted={'a': 1, 'b': 2}, delivered=[{'a': 1, 'b': 4}, {'a': 1}, {}]))
        result = summarize(source)
        self.assertEqual(result['delivery'][0]['latency_median_s'], 1.875)
        self.assertEqual(result['delivery'][0]['latency_p95_s'], 3)
        self.assertEqual(result['delivery'][1]['latency_median_s'], .75)
        self.assertIsNone(result['delivery'][2]['latency_median_s'])

    def test_missing_measurement_is_not_zero_observed(self):
        result = summarize({'status': 'incomplete'})
        self.assertIsNone(result['accepted_within'])
        self.assertFalse(result['measurement_available'])

    def test_render_raw_csv_and_offline_svg_agree(self):
        import csv
        import json
        import tempfile
        from pathlib import Path
        from report import render
        with tempfile.TemporaryDirectory(prefix='duration-report-test-') as owned:
            root = Path(owned)
            source = dict(status='completed', duration_seconds=2, measurements=dict(
                attempts=[dict(sequence=1, outcome='accepted', response_s=.5, send_started_s=.2)],
                accepted={'aa': 1}, delivered=[{'aa': 2.5}], secret='DO-NOT-RENDER'))
            (root / 'measurement.json').write_text(json.dumps(source))
            row = dict(role='generator', unix_s=100, monotonic_s=1, pid=7, start_ticks=8,
                       cpu_ticks=9, cpu_percent=50, rss_bytes=1024**2)
            (root / 'resources.jsonl').write_text(json.dumps(row) + '\n')
            result = render(root)
            self.assertEqual(result['delivery'][0]['completion_after_publication_s'], .5)
            with (root / 'accepted-eps.csv').open() as handle:
                self.assertEqual(list(csv.DictReader(handle))[0]['accepted'], '1')
            page = (root / 'report.html').read_text()
            self.assertIn('points="40.000,20.000"', page)
            for forbidden in ('DO-NOT-RENDER', '<script', 'https://', 'cdn.'):
                self.assertNotIn(forbidden, page)

    def test_svg_coordinates_are_from_raw_values(self):
        self.assertEqual(coordinates([(0, 0), (2, 4)], 2, 4), '40.000,220.000 760.000,20.000')

if __name__ == '__main__': unittest.main()
