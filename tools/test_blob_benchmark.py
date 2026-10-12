"""Regression tests for retained benchmark result validation."""
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from blob_benchmark import main, parse_records, summarize, campaign


class MainPublication(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.output = self.root / "output"
        self.example = self.repo / "crates/aster-node/examples/blob_benchmark.rs"
        self.example.parent.mkdir(parents=True)
        self.example.write_text("// fixture source\n")
        (self.repo / "Cargo.toml").write_text('[profile.release]\nopt-level = "s"\n')
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        self.binary = self.root / "fixture"
        self.addCleanup(os.umask, os.umask(0o077))

    def run_fixture(self, change_source=False):
        # A real subprocess emits a complete receipt; no transport/perf run is needed.
        script = (
            f"#!{sys.executable}\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "size = int(sys.argv[2])\n"
            "print('BENCH_RESULT ' + json.dumps(dict(status='complete', bytes=size, "
            "verified_bytes=size, source_sha256='fixture', receiver_sha256='fixture', "
            "transfer_until_ready_ns=123)))\n"
        )
        if change_source:
            script += f"Path({str(self.example)!r}).write_text('// changed during run\\n')\n"
        self.binary.write_text(script)
        self.binary.chmod(0o700)
        argv = ["blob_benchmark", "--variant", "fixture", str(self.repo), str(self.binary),
                "--output", str(self.output), "--state", str(self.root / "state"),
                "--sizes", "8192"]
        with patch.object(sys, "argv", argv):
            main()

    def test_matching_identity_publishes_read_back_summaries(self):
        self.run_fixture()
        before = json.loads((self.output / "metadata.json").read_text())["variants"]
        after = json.loads((self.output / "source-after.json").read_text())
        self.assertEqual(before, after)
        expected = [{"variant": "fixture", "bytes": 8192, "samples": 3,
                     "completed": 3, "ready_median_ns": 123}]
        self.assertEqual(json.loads((self.output / "summary.json").read_text()), expected)
        with (self.output / "summary.csv").open(newline="") as source:
            self.assertEqual(list(csv.DictReader(source)),
                             [{key: str(value) for key, value in expected[0].items()}])

    def test_identity_mismatch_retains_evidence_without_publishing_summaries(self):
        with self.assertRaisesRegex(ValueError, "source or binary changed"):
            self.run_fixture(change_source=True)
        before = json.loads((self.output / "metadata.json").read_text())["variants"]
        after = json.loads((self.output / "source-after.json").read_text())
        self.assertNotEqual(before, after)
        self.assertEqual(len(list(self.output.glob("fixture-*.json"))), 3)
        for name in ("summary.json", "summary.csv"):
            with self.subTest(name=name):
                self.assertFalse((self.output / name).exists())



class Results(unittest.TestCase):
    def test_campaign_has_all_ten_sizes_and_long_large_bounds(self):
        cases = campaign()
        self.assertEqual(sorted({c[1] for c in cases}), [8192, 98304] + [n * 1024**2 for n in (1, 4, 8, 16, 24, 32, 48, 64)])
        self.assertEqual(len(cases), 16)
        for _, size, deadline in cases:
            self.assertGreaterEqual(deadline, 180 if size == 64 * 1024**2 else size / 1024**2 * 180)

    def test_summary_counts_timeouts_but_never_pools_their_elapsed_time(self):
        runs = []
        for status, ns in [("complete", 30), ("complete", 10), ("transfer_timeout", 900)]:
            runs.append({"variant": "baseline", "exit_code": 0, "records": [{"type": "BENCH_RESULT", "data": {"status": status, "bytes": 8, "transfer_until_ready_ns": ns}}]})
        rows = summarize(runs)
        self.assertEqual(rows, [{"variant": "baseline", "bytes": 8, "samples": 3, "completed": 2, "ready_median_ns": 20}])

    def test_missing_duplicate_and_unverified_results_fail_closed(self):
        for text in ["", 'BENCH_RESULT {"status":"transfer_timeout"}\n' * 2,
                     'BENCH_RESULT {"status":"complete","bytes":8,"verified_bytes":7,"source_sha256":"a","receiver_sha256":"b"}\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_records(text)

    def test_timeout_never_becomes_completed_throughput(self):
        records = parse_records('BENCH_RESULT {"status":"transfer_timeout","bytes":64,"transfer_ns":null,"verification_ns":null,"fetched_carrier_bytes":12}\n')
        self.assertEqual(records[-1]["data"]["status"], "transfer_timeout")
        self.assertIsNone(records[-1]["data"]["transfer_ns"])


if __name__ == "__main__":
    unittest.main()
