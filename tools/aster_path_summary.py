#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Allowlisted Markdown tables only; never copy errors, credentials or payloads."""
import argparse
import json
import math
from pathlib import Path
import re
import os

PROFILES = ('baseline', 'impaired', 'reorder', 'outage')
STATUSES = ('pass', 'fail', 'verified', 'running', 'success', 'failure', 'cancelled', 'skipped')


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def measurements(row, role):
    samples = [s[role] for s in row.get('samples', []) if isinstance(s, dict) and isinstance(s.get(role), dict)]
    rss = [s['rss_bytes'] for s in samples if number(s.get('rss_bytes'))]
    ticks = elapsed = 0
    for a, b in zip(samples, samples[1:]):
        keys = ('monotonic', 'cpu_ticks', 'clock_ticks_per_second')
        if (not all(number(s.get(k)) for s in (a, b) for k in keys)
                or a.get('agent_pid') != b.get('agent_pid') or not a.get('agent_pid')
                or a['clock_ticks_per_second'] != b['clock_ticks_per_second']
                or a['clock_ticks_per_second'] == 0):
            continue
        dt, dc = b['monotonic'] - a['monotonic'], b['cpu_ticks'] - a['cpu_ticks']
        if dt > 0 and dc >= 0:
            ticks += dc / a['clock_ticks_per_second']
            elapsed += dt
    return (f'{max(rss) / 1048576:.2f}' if rss else '—',
            f'{100 * ticks / elapsed:.2f}' if elapsed else '—')


def render(root, env):
    lines = ['| Stage | Outcome |', '| --- | --- |']
    for label, key in [('Preflight', 'PREFLIGHT_OUTCOME'), ('Canonical image build', 'BUILD_OUTCOME'), ('Controller step', 'RUN_OUTCOME')]:
        value = env.get(key)
        lines.append(f'| {label} | {value if value in STATUSES else "not available"} |')
    for label, name in [('Build', 'build-exit-code'), ('Controller', 'run-exit-code')]:
        try:
            code = (root / name).read_text().strip()
        except OSError:
            code = ''
        if re.fullmatch(r'[0-9]{1,3}', code):
            outcome = 'timeout' if code == '124' else 'killed (possible timeout)' if code == '137' else 'exit'
            lines.append(f'| {label} exit | {outcome} ({int(code)}) |')
    receipt = None
    try:
        receipt = json.loads((root / 'receipt.json').read_text())
        if not isinstance(receipt, dict):
            raise ValueError('invalid receipt')
        status = receipt.get('status')
        lines.append(f'| Campaign | {status if status in STATUSES else "unknown"} |')
    except (OSError, ValueError):
        lines.append('| Campaign | No receipt or unreadable receipt; no PASS established |')
    lines += ['', '| Requested input | Value |', '| --- | --- |']
    for key in ('AGENTS', 'EVENTS', 'PAYLOAD', 'RATE', 'CPU', 'MEMORY', 'DEADLINE', 'STORAGE_ITEMS', 'STORAGE_MIB', 'PROFILE'):
        value = env.get(key, '')
        if (key == 'PROFILE' and value in (*PROFILES, 'all')) or (key != 'PROFILE' and re.fullmatch(r'[0-9]{1,12}(\.[0-9]{1,6})?', value)):
            lines.append(f'| {key} | {value} |')
    lines += ['', '| Profile | Status | Agent | Accepted | Observed deliveries | Peerless exact | Sampled peak RSS MiB | CPU % (one core) |',
              '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |']
    rows = {r.get('profile'): r for r in (receipt or {}).get('profiles', []) if isinstance(r, dict)}
    for profile in PROFILES:
        row = rows.get(profile)
        if row is None:
            try:
                row = json.loads((root / (profile + '.json')).read_text())
            except (OSError, ValueError):
                continue
        if not isinstance(row, dict):
            continue
        status = row.get('status')
        status = status if status in STATUSES else 'unknown'
        for role in (f'node-{chr(97 + i)}' for i in range(20)):
            accepted = row.get('accepted', {}).get(role)
            delivered = row.get('deliveries', {}).get(role)
            if not isinstance(accepted, dict) or not isinstance(delivered, dict):
                continue
            exact = row.get('peerless', {}).get(role, {}).get('exact_events')
            exact = exact if isinstance(exact, int) and not isinstance(exact, bool) and exact >= 0 else '—'
            rss, cpu = measurements(row, role)
            lines.append(f'| {profile} | {status} | {role} | {len(accepted)} | {len(delivered)} | {exact} | {rss} | {cpu} |')
    lines += ['', '| Measurement boundary | Meaning |', '| --- | --- |',
              '| Resource samples | Agent PID only; CPU uses same-PID, non-reset counter intervals, 100% = one core. RSS is sampled, not an absolute peak. |',
              '| Counts | Observed deliveries may include local Events; only completed exact checks establish delivery/reopen success. Missing evidence is —. |',
              '| Scope | One-host Docker diagnostic, not production or full scale qualification. See retained JSON/log artifacts for failures. |']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('a') as output:
        output.write(render(args.input, os.environ))


if __name__ == '__main__':
    main()
