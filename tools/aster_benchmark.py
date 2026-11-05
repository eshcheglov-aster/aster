#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Payload-free duration benchmark statistics and offline reports."""
import math
import statistics
import os
from pathlib import Path
import threading
import time
import csv
import html
import json
import re

ROLES = tuple(f'node-{chr(97 + i)}' for i in range(20))
PROFILES = ('baseline', 'impaired', 'reorder', 'outage')
COUNTS = ('attempts', 'accepted_during', 'accepted_later', 'rejected', 'unknown', 'actual_events_per_second')
RESOURCES = ('pid', 'start_ticks', 'monotonic', 'cpu_seconds', 'rss_bytes', 'cpu_percent')
COLORS = ('#2563eb', '#dc2626', '#059669', '#9333ea', '#ea580c', '#0891b2', '#be185d', '#65a30d', '#4f46e5', '#a16207')


def numbers(source, keys):
    return {key: value for key in keys if (value := source.get(key)) is None or
            (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value))}


def public_report(source):
    """Serialize only known telemetry. No Event contents, keys or RPC errors."""
    result: dict = {'schema': 'aster-duration-benchmark/v1'}
    if source.get('status') in ('running', 'completed', 'error', 'verified', 'pass', 'fail'):
        result['status'] = source['status']
    result['error_present'] = bool(source.get('error_present') or source.get('error') or source.get('provenance_error') or source.get('cleanup_errors'))
    cleanup_count = source.get('cleanup_error_count', len(source.get('cleanup_errors', [])))
    result['cleanup_error_count'] = cleanup_count if isinstance(cleanup_count, int) and not isinstance(cleanup_count, bool) and cleanup_count >= 0 else None
    result['configuration'] = numbers(source.get('configuration', {}), ('agents', 'duration_seconds', 'events_per_second', 'payload_bytes', 'cpu_limit', 'memory_mib', 'storage_max_items', 'storage_mib', 'restore_deadline_seconds', 'bandwidth_kbit', 'delay_ms', 'jitter_ms', 'loss_percent', 'rate_mbit', 'reorder_percent', 'outage_seconds', 'outage_at_seconds'))
    if source.get('error_code') == 'source-drift' or 'source/helper drift' in str(source.get('error', '')):
        result['error_code'] = 'source-drift'
    elif source.get('error_code') == 'content-mismatch' or 'mismatched Event' in str(source.get('error', '')):
        result['error_code'] = 'content-mismatch'
    for key, allowed in (
            ('error_stage', ('setup', 'publish-and-continuous-consume', 'outage-applied',
                'confirmed-outage-witness', 'drain', 'stop-all', 'peerless-reopen', 'cleanup', 'campaign')),
            ('error_reason', ('deadline-exceeded', 'interrupted', 'execution-failed',
                'invalid-evidence', 'io-failed', 'rpc-failed', 'unexpected-error'))):
        if source.get(key) in allowed:
            result[key] = source[key]
    if source.get('error_kind') in ('ExecutionError', 'ValueError', 'TimeoutError', 'OSError', 'KeyboardInterrupt', 'RpcError'):
        result['error_kind'] = source['error_kind']
        result.setdefault('error_reason', {'TimeoutError': 'deadline-exceeded',
            'KeyboardInterrupt': 'interrupted', 'ExecutionError': 'execution-failed',
            'ValueError': 'invalid-evidence', 'OSError': 'io-failed',
            'RpcError': 'rpc-failed'}[source['error_kind']])
    for key in ('source_head', 'source_diff_sha256', 'image_id', 'production_binary_sha256'):
        value = source.get(key, '')
        if isinstance(value, str) and re.fullmatch(r'(sha256:)?[0-9a-f]{40,64}', value):
            result[key] = value
    if source.get('profile') in PROFILES:
        result['profile'] = source['profile']
    if 'profiles' in source:
        result['profiles'] = [public_report(row) for row in source['profiles'] if row.get('profile') in PROFILES]
    result['measurement'] = numbers(source.get('measurement', {}), ('start_monotonic', 'end_monotonic', 'duration_seconds'))
    result['benchmark'], result['benchmark_resources'], result['delivery_counts'] = {}, {}, {}
    result['resource_limits'] = {role: numbers(source['resource_limits'][role], ('NanoCpus', 'Memory', 'MemorySwap'))
        for role in ROLES if role in source.get('resource_limits', {})}
    result['outage_restoration'] = numbers(source.get('outage_restoration', {}),
        ('apply_started_monotonic', 'applied_monotonic', 'restore_target_monotonic', 'restore_started_monotonic', 'restored_monotonic'))
    result['helper_files_sha256'] = {name: digest for name, digest in source.get('helper_files_sha256', {}).items()
        if name in ('aster_path_diagnostic.py', 'aster_benchmark.py', 'aster_mesh_playground.py', 'aster_lan_mvp.py', 'aster_path_delivery.py')
        and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)}
    for role in ROLES:
        if role in source.get('benchmark', {}):
            row = source['benchmark'][role]
            result['benchmark'][role] = dict(numbers(row, COUNTS), latency_seconds=numbers(row.get('latency_seconds', {}), ('count', 'median', 'p95', 'max')))
            result['benchmark'][role]['responses'] = [dict(numbers(sample, ('submitted_seconds', 'completed_seconds', 'latency_seconds')),
                outcome=sample['outcome']) for sample in row.get('responses', []) if sample.get('outcome') in ('accepted', 'rejected')]
        if role in source.get('delivery_counts', {}):
            result['delivery_counts'][role] = numbers(source['delivery_counts'][role], ('unique', 'missing'))
        if role in source.get('benchmark_resources', {}):
            result['benchmark_resources'][role] = []
            for row in source['benchmark_resources'][role]:
                clean = numbers(row, ('monotonic', 'accepted', 'delivered'))
                clean['processes'] = {name: numbers(sample, RESOURCES) if isinstance(sample, dict) else None
                    for name in ('agent', 'generator', 'sdk') if (sample := row.get('processes', {}).get(name)) is not None}
                result['benchmark_resources'][role].append(clean)
    return result


def display(value):
    return '—' if value is None else f'{value:.3f}' if isinstance(value, float) else str(value)


def chart(series, title, duration):
    points = [(t, v) for _, rows in series for t, v in rows if v is not None]
    xmax = max([duration, 1] + [t for t, _ in points])
    ymax = max([1] + [v for _, v in points])
    parts = [f'<h3>{html.escape(title)}</h3><svg viewBox="0 0 1000 250" role="img" aria-label="{html.escape(title, quote=True)}">',
             '<path d="M65 15 V215 H980" fill="none" stroke="#94a3b8"/>',
             f'<text x="2" y="25">{ymax:.1f}</text><text x="2" y="215">0</text>',
             f'<text x="65" y="245">0 s</text><text x="920" y="245">{xmax:.1f} s</text>']
    for index, (name, rows) in enumerate(series):
        color = COLORS[index % len(COLORS)]
        segment = []
        for t, value in rows + [(0, None)]:
            if value is None:
                if segment:
                    parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{" ".join(segment)}"/>')
                    if len(segment) == 1:
                        x, y = segment[0].split(',')
                        parts.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{color}"/>')
                    segment = []
            else:
                segment.append(f'{65 + max(0,t)/xmax*915:.2f},{215-value/ymax*195:.2f}')
    parts.append('</svg><p>')
    parts += [f'<span style="color:{COLORS[i % len(COLORS)]}">{html.escape(name)}</span> ' for i, (name, _) in enumerate(series)]
    return ''.join(parts) + '</p>'


def render_html(report, title='Aster duration benchmark'):
    report = public_report(report)
    parts = ['<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">',
        '<style>body{font:15px system-ui;margin:2rem;color:#172033;background:#fff}table{border-collapse:collapse}td,th{padding:.5rem;border:1px solid #ddd}svg{width:100%;max-height:300px}text{font:12px system-ui}span{margin-right:1em}</style>',
        f'<title>{html.escape(title)}</title><h1>{html.escape(title)}</h1>',
        '<p>Workload metrics have no performance pass/fail threshold. CPU 100% = one core; RSS peaks are sampled. Latency measures generator submission to client-observed accepted response, including queueing. Missing samples are gaps. Unknown includes unconfirmed or unsent submissions at cutoff.</p>']
    rows = report.get('profiles', [report])
    if 'profiles' in report and report['error_present']:
        rows = [report, *rows]
    for row in rows:
        parts.append(f'<h2>{html.escape(row.get("profile", "campaign"))}: {html.escape(row.get("status", "unknown"))}</h2>')
        if row['error_present']:
            parts.append('<p>Run error recorded; incomplete evidence. '
                         + html.escape(' / '.join(row.get(key, 'unavailable') for key in
                             ('error_stage', 'error_reason', 'error_kind')))
                         + '. Inspect controller logs.</p>')
        headings = ('Agent', 'Attempts', 'Accepted during', 'Accepted later', 'Rejected', 'Unknown', 'Actual Events/s', 'Delivered unique', 'Missing', 'Latency median s', 'p95 s', 'max s', 'Peak RSS MiB')
        parts.append('<table><tr>' + ''.join(f'<th>{s}</th>' for s in headings) + '</tr>')
        origin = row.get('measurement', {}).get('start_monotonic') or 0
        duration = row.get('measurement', {}).get('duration_seconds') or 0
        for role, stats in row['benchmark'].items():
            delivery = row['delivery_counts'].get(role, {})
            rss = [sample['rss_bytes'] for sample_row in row['benchmark_resources'].get(role, [])
                   if (sample := sample_row.get('processes', {}).get('agent')) and sample.get('rss_bytes') is not None]
            values = [role] + [stats.get(k) for k in COUNTS] + [delivery.get(k) for k in ('unique', 'missing')] + [stats['latency_seconds'].get(k) for k in ('median', 'p95', 'max')] + [max(rss)/1048576 if rss else None]
            parts.append('<tr>' + ''.join(f'<td>{html.escape(display(v))}</td>' for v in values) + '</tr>')
        parts.append('</table>')
        for process in ('agent', 'generator', 'sdk'):
            for metric, label, scale in (('cpu_percent', 'CPU %', 1), ('rss_bytes', 'RSS MiB', 1048576)):
                series = []
                for role, rows in row['benchmark_resources'].items():
                    values = []
                    for sample in rows:
                        if sample.get('monotonic') is None:
                            continue
                        t = sample['monotonic'] - origin
                        if t < 0:
                            continue
                        value = (sample.get('processes', {}).get(process) or {}).get(metric)
                        values.append((t, value / scale if value is not None else None))
                    series.append((role, values))
                parts.append(chart(series, process + ' ' + label, duration))
        series = []
        for role, rows in row['benchmark_resources'].items():
            values = []
            for a, b in zip(rows, rows[1:]):
                if any(s.get(k) is None for s in (a, b) for k in ('monotonic', 'accepted')):
                    continue
                dt = b['monotonic'] - a['monotonic']
                if a['monotonic'] >= origin and dt > 0:
                    values.append((b['monotonic'] - origin, (b['accepted'] - a['accepted']) / dt))
            series.append((role, values))
        parts.append(chart(series, 'Accepted responses / second (actual observation intervals)', duration))
    return '\n'.join(parts)


def write_artifacts(root, report):
    public = public_report(report)
    (root / 'benchmark.json').write_text(json.dumps(public, indent=2) + '\n')
    (root / 'report.html').write_text(render_html(public))
    with (root / 'publications.csv').open('w', newline='') as output:
        writer = csv.writer(output)
        fields = ('submitted_seconds', 'completed_seconds', 'latency_seconds', 'outcome')
        writer.writerow(('profile', 'agent', *fields))
        for row in public.get('profiles', []):
            for role, stats in row['benchmark'].items():
                for sample in stats['responses']:
                    writer.writerow((row['profile'], role, *(sample.get(k) for k in fields)))
    with (root / 'resources.csv').open('w', newline='') as output:
        writer = csv.writer(output)
        writer.writerow(('profile', 'agent', 'process', 'elapsed_seconds', 'accepted', 'delivered', *RESOURCES))
        for row in public.get('profiles', []):
            origin = row['measurement'].get('start_monotonic') or 0
            for role, samples in row['benchmark_resources'].items():
                for sample in samples:
                    elapsed = sample['monotonic'] - origin if sample.get('monotonic') is not None else None
                    for process in ('agent', 'generator', 'sdk'):
                        resource = sample['processes'].get(process) or {}
                        writer.writerow((row['profile'], role, process, elapsed,
                                         sample.get('accepted'), sample.get('delivered'), *(resource.get(k) for k in RESOURCES)))


def cpu_percent(previous, current):
    if not previous or not current:
        return None
    if any(previous.get(key) != current.get(key) for key in ('pid', 'start_ticks')):
        return None
    dt = current['monotonic'] - previous['monotonic']
    dc = current['cpu_seconds'] - previous['cpu_seconds']
    return 100 * dc / dt if dt > 0 and dc >= 0 else None


def process_sample(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'monotonic': time.monotonic(), 'pid': pid, 'start_ticks': int(fields[19]),
                'cpu_seconds': (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
                'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE')}
    except (OSError, ValueError, IndexError):
        return None


class ResourceObserver:
    """Independent local procfs sampling; never waits for an application RPC."""
    def __init__(self, processes, counters=lambda: {}):
        self.processes, self.counters = processes, counters
        self.rows, self.previous = [], {}
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, name='benchmark-resources')
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            row = {'monotonic': time.monotonic(), **self.counters(), 'processes': {}}
            for name, pid in self.processes().items():
                sample = process_sample(pid)
                if sample is not None:
                    sample['cpu_percent'] = cpu_percent(self.previous.get(name), sample)
                self.previous[name] = sample
                row['processes'][name] = sample
            with self.lock:
                self.rows.append(row)
            self.stop.wait(1)

    def snapshot(self):
        with self.lock:
            return list(self.rows)

    def close(self):
        self.stop.set()
        self.thread.join(2)



def quantiles(values):
    """Exact median and nearest-rank p95 over all observed completions."""
    values = sorted(values)
    if not values:
        return {'count': 0, 'median': None, 'p95': None, 'max': None}
    return {'count': len(values), 'median': statistics.median(values),
            'p95': values[math.ceil(.95 * len(values)) - 1], 'max': values[-1]}


class PublicationStatistics:
    """Attempts are generator submissions; latency ends at observed response.

    Keys are local opaque identities, never serialized. Unresolved submissions
    remain unknown, including a submission that the SDK has not sent yet.
    """
    def __init__(self, start, duration, maximum_attempts=10000):
        if not math.isfinite(start) or not math.isfinite(duration) or duration <= 0:
            raise ValueError('invalid measurement interval')
        self.start, self.end = start, start + duration
        self.maximum_attempts = maximum_attempts
        self.attempts = {}
        self.results = {}

    def attempt(self, key, at):
        if len(self.attempts) >= self.maximum_attempts:
            raise ValueError('diagnostic telemetry capacity exceeded')
        if not self.start <= at < self.end or key in self.attempts:
            raise ValueError('duplicate or out-of-interval attempt')
        self.attempts[key] = at

    def complete(self, key, outcome, at):
        if key in self.results:
            return
        if outcome not in ('accepted', 'rejected') or key not in self.attempts or at < self.attempts[key]:
            raise ValueError('invalid completion')
        self.results[key] = (outcome, at)

    def summary(self):
        # The publisher is the sole writer; copy before the observer iterates.
        results = self.results.copy()
        attempts = self.attempts.copy()
        accepted = [at for outcome, at in results.values() if outcome == 'accepted']
        during = sum(self.start <= at < self.end for at in accepted)
        return {'attempts': len(attempts), 'accepted_during': during,
                'responses': [{'submitted_seconds': attempts[key] - self.start, 'completed_seconds': at - self.start,
                    'latency_seconds': at - attempts[key], 'outcome': outcome} for key, (outcome, at) in results.items()],
                'accepted_later': len(accepted) - during,
                'rejected': sum(outcome == 'rejected' for outcome, _ in results.values()),
                'unknown': len(attempts) - len(results),
                'actual_events_per_second': during / (self.end - self.start),
                'latency_seconds': quantiles([at - attempts[key] for key, (outcome, at)
                                             in results.items() if outcome == 'accepted'])}
