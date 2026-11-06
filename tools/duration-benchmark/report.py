#!/usr/bin/env python3
"""Offline summary, CSV and SVG from retained measurements (no third-party assets)."""
import csv
import html
import json
import math
from pathlib import Path
import statistics
import sys


def summarize(source):
    m = source.get('measurements', {})
    duration = source.get('duration_seconds', 0)
    publishers = source.get("publisher_nodes", 1)
    attempts = m.get('attempts', [])
    accepted = [r for r in attempts if r['outcome'] == 'accepted']
    within = [r for r in accepted if 0 <= r['response_s'] < duration]
    eps = [0] * math.ceil(duration)
    for row in within:
        eps[int(row['response_s'])] += 1
    latencies = sorted(r['response_s'] - r['send_started_s'] for r in accepted)
    ids = set(m.get('accepted', {}))
    sent = {r['event_id']: r['send_started_s'] for r in accepted if r.get('event_id')}
    delivery = []
    for node, seen in enumerate(m.get('delivered', [])):
        matched = ids.intersection(seen)
        delays = sorted(seen[k] - sent[k] for k in matched if k in sent)
        delivery.append(dict(node=node, delivered=len(matched), pending=len(ids - matched),
                             latency_median_s=statistics.median(delays) if delays else None,
                             latency_p95_s=delays[math.ceil(.95 * len(delays))-1] if delays else None,
                             completion_after_publication_s=max(0, max(seen[k] for k in ids) - duration)
                             if ids and ids <= set(seen) else None))
    result = dict(status='completed' if source.get('status') == 'completed' else 'incomplete',
                offered_per_agent_rate=source.get("rate"),
                offered_total_rate=source.get("rate", 0) * publishers,
                publishers=publishers,
                errors=m.get("errors", []),
                measurement_available='measurements' in source,
                accepted_within=len(within), accepted_after=len(accepted) - len(within),
                rejected=sum(r['outcome'] == 'rejected' for r in attempts),
                unresolved=sum(r['outcome'] == 'unresolved' for r in attempts),
                not_generated=max(0, publishers * math.ceil(duration * source['rate']) - len(attempts)) if source.get('rate', 0) > 0 else None,
                unsent=sum(r['outcome'] == 'unsent' for r in attempts),
                accepted_per_second=len(within) / duration if duration else None,
                latency_median_s=statistics.median(latencies) if latencies else None,
                latency_p95_s=latencies[math.ceil(.95 * len(latencies))-1] if latencies else None,
                eps=eps, delivery=delivery)
    result['publication_by_agent'] = [dict(
        node=node,
        accepted_within=sum(r.get('publisher_node', 0) == node for r in within),
        accepted_after=sum(r.get('publisher_node', 0) == node and r['response_s'] >= duration for r in accepted),
        accepted_per_second=sum(r.get('publisher_node', 0) == node for r in within) / duration if duration else None,
    ) for node in range(publishers)]
    if not result['measurement_available']:
        for key in ('accepted_within', 'accepted_after', 'rejected', 'unresolved', 'unsent'):
            result[key] = None
    return result


def coordinates(points, xmax, ymax):
    return ' '.join(f'{40 + 720*x/max(xmax, 1e-12):.3f},{220 - 200*y/max(ymax, 1e-12):.3f}' for x, y in points)


def chart(title, series, units):
    points = [p for _, seq in series for p in seq]
    xmax = max((p[0] for p in points), default=1) or 1
    ymax = max((p[1] for p in points), default=1) or 1
    colors = ['#135aba', '#b43a28', '#24874b', '#8a46ab', '#a5750e', '#277b86']
    out = [f'<h2>{html.escape(title)}</h2>', '<svg viewBox="0 0 800 260" role="img">',
           '<path d="M40 20 V220 H760" fill="none" stroke="#777"/>',
           f'<text x="40" y="250">0</text><text x="630" y="250">{xmax:.2f} seconds</text>',
           f'<text x="40" y="15">{ymax:.2f} {html.escape(units)}</text>']
    for i, (name, seq) in enumerate(series):
        out.append(f'<polyline data-series="{html.escape(name)}" points="{coordinates(seq, xmax, ymax)}" fill="none" stroke="{colors[i % len(colors)]}"/>')
    out.append('</svg><p>' + ' · '.join(f'<span style="color:{colors[i % len(colors)]}">{html.escape(name)}</span>' for i, (name, _) in enumerate(series)) + '</p>')
    return ''.join(out)


def write_csv(path, rows, fields):
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)


def render(root):
    root = Path(root)
    path = root / 'measurement.json'
    source = json.loads(path.read_text()) if path.exists() else dict(status='incomplete')
    summary = summarize(source)
    control = root / 'controller.json'
    if control.exists():
        controller = json.loads(control.read_text())
        if controller['returncode'] or controller['errors']:
            summary['status'] = 'incomplete'
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    m = source.get('measurements', {})
    write_csv(root / 'attempts.csv', m.get('attempts', []), ['publisher_node', 'operation_sequence', 'sequence', 'due_s', 'send_started_s', 'send_completed_s', 'response_s', 'outcome', 'event_id', 'result_acknowledged', 'result_acknowledged_s'])
    write_csv(root / 'accepted-eps.csv', [dict(second=i, accepted=count) for i, count in enumerate(summary['eps'])], ['second', 'accepted'])
    resources = [json.loads(line) for line in (root / 'resources.jsonl').read_text().splitlines()] if (root / 'resources.jsonl').exists() else []
    write_csv(root / 'resources.csv', resources, ['role', 'unix_s', 'monotonic_s', 'pid', 'start_ticks', 'cpu_ticks', 'cpu_percent', 'rss_bytes'])
    sent = {r['event_id']: r['send_started_s'] for r in m.get('attempts', []) if r.get('event_id')}
    delivery_rows = [dict(node=i, event_id=id, observed_s=seen[id],
                          latency_s=seen[id] - sent[id] if id in sent else None) for i, seen in enumerate(m.get('delivered', [])) for id in m.get('accepted', {}) if id in seen]
    write_csv(root / 'delivery.csv', delivery_rows, ['node', 'event_id', 'observed_s', 'latency_s'])
    def display(value):
        if value is None:
            return 'unavailable'
        return f'{value:.3f}' if isinstance(value, float) else str(value)

    status = 'Completed' if summary['status'] == 'completed' else 'Incomplete'
    parts = ['<!doctype html><meta charset="utf-8"><title>Aster Event publication and delivery benchmark</title>',
             '<style>body{font:16px system-ui;max-width:1050px;margin:2em auto;padding:1em}svg{width:100%;background:#f4f6f8}table{border-collapse:collapse}td,th{border:1px solid #aaa;padding:.5em}</style>',
             '<h1>Event publication and delivery benchmark</h1>', f'<p>Status: <b>{status}</b></p>',
             '<p>Each agent publishes to every agent, including itself. Counts below combine all publishers. Incomplete means the run stopped before completing its checks; it does not establish Event loss.</p>',
             f'<p>Agents: {display(source.get("publisher_nodes"))}. Publication duration: {display(source.get("duration_seconds"))} s. '
             f'Offered rate per agent: {"unpaced" if source.get("rate") == 0 else display(source.get("rate")) + " Events/s"}. '
             f'In-flight limit per agent: {display(source.get("application_window"))} publications, through result acknowledgement.</p>',
             '<h2>Publication outcomes (all agents)</h2>',
             '<table><tr><th>Accepted during publication</th><th>Accepted after publication</th><th>Capacity rejected</th><th>Outcome unknown</th><th>Not sent</th></tr>',
             '<tr>' + ''.join(f'<td>{display(summary[k])}</td>' for k in ['accepted_within', 'accepted_after', 'rejected', 'unresolved', 'unsent']) + '</tr></table>',
             '<p>Acceptance counts use client response times: during publication means [0, duration); after publication means at or after duration. Outcome unknown means the generator recorded a send start without a confirmed acceptance or capacity rejection. A send start does not prove server receipt. Not sent counts generated intents with no send start.</p>',
             f'<p>Aggregate accepted rate during publication: {display(summary["accepted_per_second"])} Events/s (total accepted divided by publication duration).</p>',
             '<h2>Publication response latency</h2>',
             f'<p>Median: {display(summary["latency_median_s"])} s; p95 (nearest rank): {display(summary["latency_p95_s"])} s.</p>',
             '<p>From send start to client response, including local queues, transport and server work. Includes accepted responses after publication ends; excludes delivery to consumers.</p>']
    parts.append(f'<p>Scheduled attempts not generated: {display(summary["not_generated"]) if source.get("rate") != 0 else "not applicable without a paced schedule"}.</p>')
    origin = min((r['monotonic_s'] for r in resources), default=0)
    roles = sorted(set(r['role'] for r in resources))
    for field, label, scale, units in [('cpu_percent', 'Process CPU (100% = one core; includes setup)', 1, '%'), ('rss_bytes', 'Process memory (RSS; includes setup)', 1024**2, 'MiB')]:
        series = [(role, [(r['monotonic_s']-origin, r[field]/scale) for r in resources if r['role'] == role and r[field] is not None]) for role in roles]
        parts.append(chart(label, series, units))
    parts.append(chart('Accepted Events per second (all agents)', [('All publishers', list(enumerate(summary['eps'])))], 'Events'))
    series = []
    for node, seen in enumerate(m.get('delivered', [])):
        times = sorted(seen[k] for k in m.get('accepted', {}) if k in seen)
        series.append((f'agent-{node}', [(0, 0)] + [(t, i+1) for i, t in enumerate(times)]))
    parts.append(chart('Confirmed Event deliveries by agent', series, 'Events'))
    parts.append('<h2>Delivery of confirmed accepted Events</h2><table><tr><th>Agent</th><th>Observed</th><th>Not yet observed</th><th>Completion after publication (s)</th><th>Latency median (s)</th><th>Latency p95 (s)</th></tr>')
    for row in summary['delivery']:
        parts.append('<tr>' + ''.join(f'<td>{display(row[k])}</td>' for k in ['node', 'delivered', 'pending', 'completion_after_publication_s', 'latency_median_s', 'latency_p95_s']) + '</tr>')
    parts.append('</table><p>Delivery latency runs from send start to first consumer observation, including polling delay. Percentiles use observed confirmed IDs only. Completion measures time after publication ends until the agent has observed all confirmed IDs, with a minimum of zero. No accepted Events means no completion time. Resource charts start at the first sample; publication and delivery charts start at publication. Unavailable means no measurement; JSON and CSV retain full precision.</p>')
    (root / 'report.html').write_text(''.join(parts))
    lines = ['| Status | Accepted during publication | Accepted after publication | Capacity rejected | Outcome unknown | Not sent |', '|---|---:|---:|---:|---:|---:|', '| ' + status + ' | ' + ' | '.join(display(summary[k]) for k in ['accepted_within', 'accepted_after', 'rejected', 'unresolved', 'unsent']) + ' |', '', 'Counts combine all publishers. Outcome unknown: send started without a confirmed outcome. Not sent: generated intent with no send start. Incomplete does not establish Event loss. See report.html for rates, latency and delivery progress.']
    (root / 'summary.md').write_text('\n'.join(lines) + '\n')
    return summary

if __name__ == '__main__':
    render(sys.argv[1])
