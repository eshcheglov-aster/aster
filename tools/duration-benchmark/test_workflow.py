"""Manual workflow contract, without YAML dependencies or real workloads."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/diagnostic-runtime-volume.yml'
SCRIPT = ROOT / 'tools/duration-benchmark/ci-run.sh'


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.env = dict(os.environ, AGENTS='2', DURATION='60', RATE='10',
                        PAYLOAD='256', WINDOW='8', OVERALL='1800')

    def test_manual_identity_inputs_and_pins(self):
        self.assertTrue(self.text.startswith('name: "Benchmark: Event publication and delivery"\n'))
        self.assertIn('on:\n  workflow_dispatch:\n    inputs:', self.text)
        inputs = dict(re.findall(r'^      (\w+):\n.*?        default: \'([^\']+)\'',
                                 self.text, re.M | re.S))
        self.assertEqual(inputs, dict(agents='2', duration_seconds='60',
                                     events_per_second='10', payload_bytes='256',
                                     window='8', overall_seconds='1800'))
        for env, field in [('AGENTS', 'agents'), ('DURATION', 'duration_seconds'),
                           ('RATE', 'events_per_second'), ('PAYLOAD', 'payload_bytes'),
                           ('WINDOW', 'window'), ('OVERALL', 'overall_seconds')]:
            self.assertIn(f'{env}: ${{{{ inputs.{field} }}}}', self.text)
        for action in re.findall(r'uses: (\S+)', self.text):
            self.assertRegex(action, r'^[\w/-]+@[0-9a-f]{40}$')
        self.assertNotIn('${{ inputs.', '\n'.join(
            line for line in self.text.splitlines() if line.startswith('          ')))
        for forbidden in ('pull_request:', 'push:', 'sudo ', '--privileged',
                          '--network=host', 'docker system prune', 'continue-on-error:'):
            self.assertNotIn(forbidden, self.text)
        self.assertIn('retention-days: 14', self.text)
        self.assertIn('persist-credentials: false', self.text)
        self.assertIn('permissions:\n  contents: read', self.text)

    def test_validation_and_invalid_values(self):
        for rate in ['10', 'max', '0']:
            result = subprocess.run(['bash', str(SCRIPT), 'validate'],
                                    env=dict(self.env, RATE=rate), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        for key, value in [('AGENTS', '1'), ('AGENTS', '17'), ('DURATION', 'nan'),
                           ('DURATION', '601'), ('RATE', 'inf'), ('RATE', '-1'),
                           ('RATE', '$(touch SHOULD_NOT_EXIST)'), ('PAYLOAD', '1025'),
                           ('WINDOW', '9'), ('OVERALL', '60'), ('OVERALL', '3601')]:
            with self.subTest(key=key, value=value):
                result = subprocess.run(['bash', str(SCRIPT), 'validate'],
                                        env=dict(self.env, **{key: value}), capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_real_shell_argument_boundaries_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            timeout = directory / 'timeout'
            timeout.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                               'open(os.environ["CAPTURE"], "w").write(json.dumps(sys.argv[1:]))\n'
                               'sys.exit(23)\n')
            timeout.chmod(0o700)
            output = str(directory / 'output with spaces; $literal')
            env = dict(self.env, PATH=f'{directory}:{os.environ["PATH"]}',
                       CAPTURE=str(directory / 'args.json'), BENCHMARK_OUTPUT=output, RATE='max')
            result = subprocess.run(['bash', str(SCRIPT), 'run'], env=env, capture_output=True)
            self.assertEqual(result.returncode, 23)
            args = json.loads((directory / 'args.json').read_text())
            self.assertEqual(args[:6], ['--signal=TERM', '--kill-after=60s', '75m',
                                        'python3', '-u', 'tools/duration-benchmark/controller.py'])
            options = dict(zip(args[6::2], args[7::2]))
            # Exercise the workflow's actual logging pipeline with Actions' Bash flags.
            block = self.text.split('name: Run publication and delivery benchmark', 1)[1]
            block = block.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0]
            (directory / 'artifacts/duration-benchmark').mkdir(parents=True)
            # Keep the real script path while isolating the log output.
            block = block.replace('tools/duration-benchmark/ci-run.sh', str(SCRIPT))
            result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', block],
                                    cwd=directory, env=env, capture_output=True)
            self.assertEqual(result.returncode, 23)
            self.assertEqual(options, {
                '--fixture': 'target/release/aster-agent-acceptance-fixture',
                '--initializer': 'target/release/aster',
                '--generator': 'tools/duration-benchmark/target/release/aster-duration-benchmark',
                '--output': output, '--agents': '2', '--duration-seconds': '60',
                '--events-per-second': 'max', '--payload-bytes': '256',
                '--window': '8', '--overall-seconds': '1800'})

    def test_upload_exact_allowlist(self):
        block = self.text.split('name: Upload public reports and workflow logs', 1)[1]
        self.assertIn('if: ${{ always() }}', block)
        paths = block.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        actual = {line.strip() for line in paths.splitlines()}
        expected = {'artifacts/duration-benchmark/' + name for name in
                    ['preflight.log', 'build.log', 'controller.log']}
        expected.update('${{ runner.temp }}/duration-benchmark/' + name for name in [
            'measurement.json', 'controller.json', 'summary.json', 'summary.md', 'report.html',
            'attempts.csv', 'accepted-eps.csv', 'delivery.csv', 'resources.jsonl',
            'resources.csv', 'provenance.json'])
        self.assertEqual(actual, expected)

    def test_locked_build_and_shell_syntax(self):
        self.assertIn('cargo build --release --locked -p aster-agent', self.text)
        self.assertIn('--features client,acceptance-test-provider --bin aster-agent-acceptance-fixture', self.text)
        self.assertIn('-p aster-node --bin aster', self.text)
        self.assertIn('cargo build --release --locked --manifest-path tools/duration-benchmark/Cargo.toml', self.text)
        subprocess.run(['bash', '-n', str(SCRIPT)], check=True)
        blocks = re.findall(r'        run: \|\n((?:          .*\n|\n)+)', self.text)
        self.assertGreaterEqual(len(blocks), 5)
        for block in blocks:
            subprocess.run(['bash', '-n'], input=block, text=True, check=True)
        preflight = self.text.split('name: Test benchmark and workflow contracts', 1)[1]
        preflight = preflight.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / 'artifacts/duration-benchmark').mkdir(parents=True)
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c',
                                     'git() { return 23; };\n' + preflight],
                                    cwd=temporary, capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)


if __name__ == '__main__':
    unittest.main()
