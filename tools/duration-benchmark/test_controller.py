import unittest
from controller import cpu_percent, parse_stat, validate

class ControllerTests(unittest.TestCase):
    def test_cpu_same_lifetime_and_one_core(self):
        a = dict(pid=1, start_ticks=7, cpu_ticks=100, monotonic_s=2)
        b = dict(pid=1, start_ticks=7, cpu_ticks=200, monotonic_s=3)
        self.assertEqual(cpu_percent(a, b, 100), 100)
        b['start_ticks'] = 8
        self.assertIsNone(cpu_percent(a, b, 100))
    def test_stat_comm_with_spaces_and_parentheses(self):
        fields = ['S'] + ['0'] * 21
        fields[11], fields[12], fields[19], fields[21] = '10', '20', '99', '25'
        row = parse_stat('123 (a b) c) ' + ' '.join(fields), 4096, 1.5)
        self.assertEqual(row['cpu_ticks'], 30)
        self.assertEqual(row['rss_bytes'], 102400)
        self.assertEqual(row['start_ticks'], 99)
    def test_exit_sample_does_not_depend_on_any_rpc(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from controller import sample
        with patch('pathlib.Path.read_text', side_effect=ProcessLookupError):
            row = sample('agent-0', SimpleNamespace(pid=1), None)
        self.assertIsNone(row['cpu_percent'])
        self.assertIsNone(row['rss_bytes'])
        self.assertEqual(row['role'], 'agent-0')

    def test_validate(self):
        validate(2, 60, 1800, 20, 256, 10000)
        for rate in [float('nan'), float('inf'), -1]:
            with self.assertRaises(ValueError):
                validate(2, 60, 1800, rate, 256, 10000)

if __name__ == '__main__': unittest.main()
