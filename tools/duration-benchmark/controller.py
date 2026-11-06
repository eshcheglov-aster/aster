#!/usr/bin/env python3
"""Benchmark Event publication and delivery between local agents; sample process CPU and memory once per second."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time


def validate(agents, duration, overall, rate, payload, maximum):
    if not (2 <= agents <= 16 and math.isfinite(duration) and .01 <= duration <= 600
            and math.isfinite(overall) and duration < overall <= 86400
            and math.isfinite(rate) and 0 <= rate <= 100000
            and 8 <= payload <= 1024 and 1 <= maximum <= 100000):
        raise ValueError('configuration_bounds')


def parse_stat(text, page_bytes, observed):
    pid = int(text.split(' ', 1)[0])
    fields = text.rsplit(')', 1)[1].split()
    return dict(pid=pid, start_ticks=int(fields[19]),
                cpu_ticks=int(fields[11]) + int(fields[12]),
                rss_bytes=int(fields[21]) * page_bytes, monotonic_s=observed)


def cpu_percent(previous, current, ticks):
    if previous is None or any(previous[k] != current[k] for k in ('pid', 'start_ticks')):
        return None
    elapsed = current['monotonic_s'] - previous['monotonic_s']
    delta = current['cpu_ticks'] - previous['cpu_ticks']
    return 100 * delta / ticks / elapsed if elapsed > 0 and delta >= 0 else None


def sample(role, process, previous):
    observed = time.monotonic()
    try:
        row = parse_stat(Path(f'/proc/{process.pid}/stat').read_text(), os.sysconf('SC_PAGE_SIZE'), observed)
        row['cpu_percent'] = cpu_percent(previous, row, os.sysconf('SC_CLK_TCK'))
    except (FileNotFoundError, ProcessLookupError):
        row = dict(pid=process.pid, start_ticks=None, cpu_ticks=None,
                   rss_bytes=None, cpu_percent=None, monotonic_s=observed)
    row.update(role=role, unix_s=time.time())
    return row


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def sha256(path):
    with open(path, 'rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def prepare(root, agents, fixture, initializer):
    seed = root / 'seed'
    raw = subprocess.check_output([str(initializer), 'playground-init', '--nodes', str(agents), '--root', str(seed)], timeout=120, stderr=subprocess.DEVNULL).decode()
    identities = re.findall(r'PLAYGROUND_NODE index=(\d+) carrier_id=([0-9a-f]{64}) mission_id=([0-9a-f]{64})', raw)
    if [int(x[0]) for x in identities] != list(range(agents)):
        raise ValueError('initializer_identity_count')
    mesh_ports = [free_port(socket.SOCK_DGRAM) for _ in range(agents)]
    if len(set(mesh_ports)) != agents:
        raise ValueError('mesh_port_collision')
    configs, endpoints = [], []
    for i in range(agents):
        directory = root / f'agent-{i}'
        directory.mkdir(mode=0o700)
        subprocess.run([str(fixture), 'prepare', '--root', str(directory)], check=True,
                       timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        path = directory / 'agent.json'
        config = json.loads(path.read_text())
        state = Path(config['state']['directory'])
        # The existing initializer owns signing and identity generation.
        shutil.copyfile(seed / f'node-{i}' / 'identity.key', state / 'identity.key')
        shutil.copyfile(seed / f'node-{i}' / 'mission.unprotected-reference.bundle', directory / 'SECRET_PATH_CANARY-mission-bundle')
        config['mesh']['bind'] = f'127.0.0.1:{mesh_ports[i]}'
        config['mesh']['peers'] = [f'{carrier}@127.0.0.1:{mesh_ports[j]}={mission}'
                                   for j, (_, carrier, mission) in enumerate(identities) if j != i]
        path.write_text(json.dumps(config))
        subprocess.run([str(fixture), '--check-config', str(path)], check=True,
                       timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        configs.append(path)
        endpoints.append(dict(url='http://' + config['application']['listen'],
                              token_file=config['credentials']['client_token_file']))
    return configs, endpoints


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True, help='Acceptance-fixture executable')
    parser.add_argument('--initializer', type=Path, required=True, help='Aster executable for playground initialization')
    parser.add_argument('--generator', type=Path, required=True, help='Benchmark generator executable')
    parser.add_argument('--output', type=Path, required=True, help='New output directory outside the checkout')
    parser.add_argument('--agents', type=int, default=2, help='Total agents, 2–16 (default: 2)')
    parser.add_argument('--duration-seconds', type=float, default=60, help='Publication duration, 0.01–600 seconds (default: 60)')
    parser.add_argument('--overall-seconds', type=float, default=1800, help='Timeout from publication start through delivery, greater than duration and up to 86400 seconds (default: 1800); each RPC has a 900-second limit')
    parser.add_argument('--events-per-second', default='10', help='Events/second per agent, 0–100000 (default: 10); max or 0 sends without pacing')
    parser.add_argument('--payload-bytes', type=int, default=256, help='Event payload size, 8–1024 bytes (default: 256)')
    parser.add_argument('--max-attempts', type=int, default=100000, help='Publication attempt limit per agent, 1–100000 (default: 100000)')
    parser.add_argument('--window', type=int, default=8, choices=range(1, 9), help='In-flight publications per agent, through result acknowledgement (default: 8)')
    args = parser.parse_args(argv)
    rate = 0.0 if args.events_per_second == 'max' else float(args.events_per_second)
    validate(args.agents, args.duration_seconds, args.overall_seconds, rate, args.payload_bytes, args.max_attempts)
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = root / 'private'
    private.mkdir(mode=0o700)
    processes, logs, previous = {}, [], {}
    errors = []
    rc = 2
    repo = Path(__file__).resolve().parents[2]
    provenance = dict(base=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo).decode().strip(),
                      binaries={name: sha256(getattr(args, name)) for name in ('fixture', 'initializer', 'generator')},
                      source={name: sha256(Path(__file__).parent / name) for name in
                              ('Cargo.toml', 'Cargo.lock', 'src/main.rs', 'controller.py', 'report.py', 'test_controller.py', 'test_report.py', 'README.md')},
                      native_build_profile='caller-supplied; see binary hashes')
    snapshot = root / 'source-snapshot'
    snapshot.mkdir()
    for name in provenance['source']:
        target = snapshot / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(Path(__file__).parent / name, target)
    (root / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    try:
        configs, endpoints = prepare(private, args.agents, args.fixture.resolve(), args.initializer.resolve())
        for i, config in enumerate(configs):
            log = open(private / f'agent-{i}.log', 'wb'); logs.append(log)
            processes[f'agent-{i}'] = subprocess.Popen([str(args.fixture.resolve()), '--config', str(config)], stdout=log, stderr=log)
        ready_deadline = time.monotonic() + 120
        for endpoint in endpoints:
            port = int(endpoint['url'].rsplit(':', 1)[1])
            while True:
                if any(p.poll() is not None for p in processes.values()):
                    raise ValueError('agent_startup_exit')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= ready_deadline:
                        raise ValueError('agent_startup_timeout')
                    time.sleep(.1)
        config = dict(endpoints=endpoints, duration_seconds=args.duration_seconds,
                      overall_seconds=args.overall_seconds, rate=rate, payload_bytes=args.payload_bytes,
                      max_attempts=args.max_attempts, window=args.window, output=str(root))
        config_path = private / 'generator.json'
        config_path.write_text(json.dumps(config))
        log = open(private / 'generator.log', 'wb'); logs.append(log)
        generator = subprocess.Popen([str(args.generator.resolve()), str(config_path)], stdout=log, stderr=log)
        processes['generator'] = generator
        next_sample = time.monotonic()
        # Setup is excluded from the generator's own publication-relative deadline.
        watchdog = next_sample + 130 + args.overall_seconds
        with open(root / 'resources.jsonl', 'w') as resource:
            while True:
                for role, process in processes.items():
                    row = sample(role, process, previous.get(role))
                    if row['start_ticks'] is not None:
                        previous[role] = row
                    resource.write(json.dumps(row) + '\n')
                resource.flush()
                if generator.poll() is not None:
                    rc = generator.returncode
                    break
                if time.monotonic() >= watchdog:
                    raise ValueError('generator_watchdog')
                next_sample += 1
                time.sleep(max(0, next_sample - time.monotonic()))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Never retain arbitrary exception messages that may contain credentials.
        errors.append(type(error).__name__)
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
        for process in processes.values():
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
                errors.append('forced_cleanup')
        for log in logs:
            log.close()
        (root / 'controller.json').write_text(json.dumps(dict(returncode=rc, errors=errors), indent=2))
        from report import render
        render(root)
    print(root / 'report.html')
    return 0 if rc == 0 and not errors else 2

if __name__ == '__main__':
    raise SystemExit(main())
