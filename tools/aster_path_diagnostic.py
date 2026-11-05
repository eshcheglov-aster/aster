#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Opt-in bounded production Event impairment/resource diagnostic."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from aster_lan_mvp import ConnectJsonClient, RpcError, read_token_file, canonical_event_id, OperatorError
from aster_mesh_playground import NumberedPublisher, RpcError as PublicationRpcError, safe_text
from aster_path_delivery import OwnedDocker, ExecutionError, _run_command, _pinned_docker

LIB = '/usr/local/libexec/aster/'
# Complete local Python import closure, including the numbered publisher.
# Image-resident delivery entrypoints are instead bound by the immutable image ID.
HELPER_FILES = ('aster_path_diagnostic.py', 'aster_mesh_playground.py',
                'aster_lan_mvp.py', 'aster_path_delivery.py')


def source_identity(root):
    return {
        'source_head': _run_command(['git', '-C', str(root), 'rev-parse', 'HEAD'], 5).decode().strip(),
        'source_diff_sha256': hashlib.sha256(_run_command(
            ['git', '-C', str(root), 'diff', 'HEAD', '--binary'], 5)).hexdigest(),
        'helper_files_sha256': {name: hashlib.sha256((root / 'tools' / name).read_bytes()).hexdigest()
                                for name in HELPER_FILES},
    }



def verify_events(accepted, actual, *, deadline=None, exact=False):
    """Require nonvacuous matching content; optionally require identical ID sets."""
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('admitted Events not delivered before deadline')
    if not accepted:
        raise ValueError('no accepted Events')
    if exact and accepted.keys() != actual.keys():
        raise ValueError('Event ID set mismatch')
    for identity, expected in accepted.items():
        observed = actual.get(identity, {})
        if any(observed.get(key) != expected.get(key) for key in ('id', 'logicalKey', 'payload')):
            raise ValueError('missing or mismatched Event: ' + identity)
    return len(accepted)


def query_all(client, maximum):
    events, marker = {}, 0
    for _ in range(maximum + 1):
        response = client.call('QueryEvents', {
            'topic': 'mesh.messages', 'scope': 'demo/playground',
            'includeDescendantScopes': False, 'afterAcceptanceMarker': str(marker), 'limit': 128})
        for event in response.get('events', []):
            events[event['id']] = event
        if len(events) > maximum:
            raise ValueError('query Event bound exceeded')
        if not response.get('hasMore', False):
            return events
        next_marker = int(response['scannedThrough'])
        if next_marker <= marker:
            raise ValueError('query made no progress')
        marker = next_marker
    raise ValueError('query page bound exceeded')


def netem_args(profile, delay, jitter, loss, rate, reorder, *, bandwidth_kbit=None):
    if profile == 'baseline':
        result = []
    elif profile == 'outage':
        result = ['loss', '100%']
    elif profile in ('impaired', 'reorder'):
        result = ['limit', '1000', 'delay', f'{delay}ms', f'{jitter}ms', 'loss', f'{loss}%']
        if bandwidth_kbit is None:
            result += ['rate', f'{rate}mbit']
        if profile == 'reorder':
            result += ['reorder', f'{reorder}%']
    else:
        raise ValueError('unknown profile')
    if bandwidth_kbit:
        result += ['rate', f'{bandwidth_kbit}kbit']
    return result


def verify_bandwidth(rows, bandwidth_kbit):
    """tc JSON netem rate is bytes/s, not the CLI's decimal kbit/s."""
    try:
        if not rows:
            raise ValueError('missing interfaces')
        for interface in rows:
            roots = [row for row in interface if row.get('kind') == 'netem' and row.get('root')]
            if len(roots) != 1:
                raise ValueError('missing root netem')
            actual = roots[0]['options'].get('rate', {}).get('rate', 0)
            if actual != bandwidth_kbit * 125:
                raise ValueError('rate mismatch')
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ExecutionError('bandwidth readback mismatch') from error


class Worker:
    """One persistent nonroot helper per endpoint; bounded line IPC."""
    def __init__(self, argv, *, stderr=subprocess.DEVNULL):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=stderr, bufsize=0)
        self.buffer = b''

    def call(self, action, timeout=45, **arguments):
        self.process.stdin.write(json.dumps(dict(action=action, **arguments)).encode() + b'\n')
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                if not selector.select(max(0, deadline - time.monotonic())):
                    raise TimeoutError('worker response deadline: ' + action)
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise ValueError('worker closed during ' + action)
                self.buffer += chunk
                if len(self.buffer) > 128 * 1024 * 1024:
                    raise ValueError('worker response bound exceeded')
        line, self.buffer = self.buffer.split(b'\n', 1)
        response = json.loads(line)
        if 'error' in response:
            raise ValueError(response['error'])
        return response['result']

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process.stdout.close()


class PublicationWorker(Worker):
    """Bound both IPC directions so cancellation can stop a blocked SDK lane."""
    def __init__(self, argv):
        super().__init__(argv, stderr=subprocess.PIPE)
        self.cancelled = threading.Event()
        os.set_blocking(self.process.stderr.fileno(), False)
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)

    def close(self):
        self.cancelled.set()
        if self.process.poll() is None:
            self.process.terminate()
        super().close()
        self.process.stderr.close()

    def _ready(self, selector, deadline):
        while not self.cancelled.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('publication IPC deadline')
            if selector.select(min(.1, remaining)):
                return
        raise ValueError('publication worker cancelled')

    def call(self, action, timeout=35, **arguments):
        data = json.dumps(dict(action=action, **arguments)).encode() + b'\n'
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('publication request bound exceeded')
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            while data:
                self._ready(selector, deadline)
                try:
                    data = data[os.write(self.process.stdin.fileno(), data):]
                except BlockingIOError:
                    continue
            selector.unregister(self.process.stdin)
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                self._ready(selector, deadline)
                try:
                    chunk = os.read(self.process.stdout.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    try:
                        detail = os.read(self.process.stderr.fileno(), 4096).decode('utf-8', errors='replace')
                    except BlockingIOError:
                        detail = ''
                    raise ValueError('publication worker closed: ' + safe_text(detail, 400))
                self.buffer += chunk
                if len(self.buffer) > 4 * 1024 * 1024:
                    raise ValueError('publication response bound exceeded')
        line, self.buffer = self.buffer.split(b'\n', 1)
        response = json.loads(line)
        if isinstance(response, dict) and isinstance(response.get('error'), str):
            # asterctl strips untrusted remote text, retaining only SDK stage/code.
            raise ValueError(safe_text(response['error'], 400))
        if not isinstance(response, dict) or 'result' not in response:
            raise ValueError('publication worker rejected request; journal retained')
        return response['result']


def sample(client):
    pid = int(Path('/clab/state/agent.pid').read_text())
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'monotonic': time.monotonic(), 'agent_pid': pid,
            'cpu_ticks': int(fields[11]) + int(fields[12]),
            'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
            'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'),
            'application_status': client.status(),
            'queue_label': 'application delivery backlog; not Iroh send queue'}


class DiagnosticPublisher(NumberedPublisher):
    """One serialized SDK journal per publishing lane, never operation-key replay."""
    def __init__(self, *args):
        super().__init__(*args)
        self.session = None
        self.closed = False
        self.session_lock = threading.Lock()

    def connect(self, url, token_path):
        self._close_session()
        super().connect(url, token_path)

    def _close_session(self):
        with self.session_lock:
            session, self.session = self.session, None
        if session is not None:
            session.close()

    def close(self):
        with self.session_lock:
            self.closed = True
        self._close_session()

    def _run(self, action, options=(), payload=None, *, local=False, json_response=False):
        if local:
            return super()._run(action, options, payload, local=True, json_response=json_response)
        with self.session_lock:
            if self.closed:
                raise PublicationRpcError('publisher closed; original journal retained')
            if self.session is None:
                if self.host is None or self.token_path is None:
                    raise PublicationRpcError('publisher is not connected')
                self.session = PublicationWorker([
                    str(self.cli), '--token-file', str(self.token_path), '--host', self.host,
                    '--port', str(self.port), '--timeout', '10', 'publication-worker',
                    '--journal', str(self.journal), '--client-id', self.client_id])
            session = self.session
        arguments = {}
        if action == 'publish':
            values = dict(zip(options[::2], options[1::2]))
            arguments['intent'] = {'topic': values['--topic'], 'scope': values['--scope'],
                'priority': 'PRIORITY_ROUTINE',
                'logicalKey': base64.b64encode(values['--logical-key'].encode()).decode(),
                'payload': base64.b64encode(payload).decode()}
        elif options:
            arguments['sequence'] = int(options[1])
        try:
            result = session.call(action, timeout=35, **arguments)
            return result if json_response else None
        except (OSError, ValueError, TimeoutError) as error:
            self._close_session()
            raise PublicationRpcError('publication worker failed; original journal retained: ' +
                                      safe_text(str(error), 400)) from error

    def publish_event(self, key, payload):
        observed = {}

        def apply(intent, result, recovered, inserted):
            if intent.get('payload') != base64.b64encode(payload).decode():
                raise RpcError('recovered publication payload mismatch')
            if recovered and intent.get('logicalKey') != base64.b64encode(key).decode():
                raise RpcError('recovered publication logical key mismatch')
            identity = canonical_event_id(result['receipt']['eventId'])
            observed.update(id=identity, logicalKey=base64.b64encode(key).decode(),
                            payload=base64.b64encode(payload).decode())
            return identity

        try:
            response = self._run('publish', ['--topic', 'mesh.messages', '--scope', 'demo/playground',
                                             '--logical-key', key.decode('ascii')], payload, json_response=True)
            result = response['result']
            apply({'payload': base64.b64encode(payload).decode()}, result, False, response['inserted'])
            self._run('publication-ack', ['--sequence', str(result['operationSequence'])])
        except (PublicationRpcError, OperatorError, KeyError, TypeError, ValueError):
            # Recovery fences the old session and retries only its journaled
            # sequence/intent. CLI resource exhaustion alone is not a definite
            # rejection: it can also mean a response was lost after commit.
            try:
                self.recover(apply)
            except Exception as error:
                raise RpcError('numbered publication outcome unknown; original journal retained: ' +
                               safe_text(str(error), 500)) from error
            if not observed:
                raise RpcError('numbered publication outcome unknown; original journal retained')
        return observed


class PublicationLanes:
    def __init__(self, root=Path('/clab/state')):
        self.root = root
        self.local = threading.local()
        self.lock = threading.Lock()
        self.next_lane = 0
        self.publishers = []
        self.closed = False

    def close(self):
        with self.lock:
            self.closed = True
            publishers = list(self.publishers)
        for publisher in publishers:
            publisher.close()

    def publish_event(self, key, payload):
        if not hasattr(self.local, 'publisher'):
            with self.lock:
                if self.closed:
                    raise PublicationRpcError('publication lanes closed')
                lane = self.next_lane
                self.next_lane += 1
                publisher = DiagnosticPublisher(Path('/usr/local/bin/asterctl'),
                                            self.root / f'diagnostic-publication-{lane}.redb',
                                            f'path-diagnostic-{lane}')
                self.publishers.append(publisher)
            publisher.initialize()
            publisher.connect('http://127.0.0.1:8181', self.root / 'client.token')
            self.local.publisher = publisher
        return self.local.publisher.publish_event(key, payload)


def publish_one(client, key, size):
    raw_key = key.encode()
    payload = (raw_key + b':' + b'x' * size)[:size]
    return client.publish_event(raw_key, payload)


class DeliveryClient:
    """Fresh consumer-only owner, separate from every publication journal.

    This disposable worker never publishes through this identity. Any unexpected
    recovered publication is an error rather than an intent we can reconstruct.
    """
    def __init__(self, rpc):
        self.rpc = rpc
        identity = base64.b64encode(b'path-diagnostic-consumer').decode()
        recovered = rpc.call('BeginEventPublicationSession', {
            'clientId': identity, 'expectedSession': '0',
            'claimNonce': base64.b64encode(os.urandom(32)).decode()})
        if recovered.get('outstanding') or int(recovered.get('allocatedThrough', 0)):
            raise ValueError('unexpected consumer publication recovery')
        self.context = {'clientId': identity, 'session': recovered['session']}
        rpc.call('CompleteEventPublicationRecovery', {
            **self.context, 'snapshotRevision': recovered.get('snapshotRevision', '0')})

    def call(self, method, request):
        if method in ('PollEvents', 'AcknowledgeEvent'):
            request = dict(request, client=self.context)
        return self.rpc.call(method, request)

    def subscribe(self, key, topic, scope):
        return self.rpc.subscribe(key, topic, scope, self.context)

    def __getattr__(self, name):
        return getattr(self.rpc, name)


class Workload:
    """Bounded paced publishers and independent continuous consumption."""
    def __init__(self, client, subscription, prefix, count, rate, size, publisher=None):
        self.client, self.subscription = client, subscription
        self.publications = publisher if publisher is not None else client
        self.accepted, self.deliveries, self.rejected, self.errors = {}, {}, [], []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.done = False
        self.started = time.monotonic()
        self.finished = None
        self.max_schedule_lag = 0.0
        self.publisher = threading.Thread(target=self.publish_loop, args=(prefix, count, rate, size), daemon=True)
        self.consumer = threading.Thread(target=self.consume_loop, daemon=True)
        self.consumer.start()
        self.publisher.start()

    def publish_loop(self, prefix, count, rate, size):
        # Each persistent SDK lane has at most one outstanding publication.
        # Reserve two of the server's eight unauthenticated slots for the
        # independent consumer and serialized worker status requests.
        budget = 6
        slots = threading.BoundedSemaphore(budget)

        def publish(key, due):
            try:
                lag = max(0, time.monotonic() - due)
                with self.lock:
                    self.max_schedule_lag = max(self.max_schedule_lag, lag)
                    if lag > 1:
                        self.errors.append('bounded publisher could not maintain requested pace')
                        return
                result = publish_one(self.publications, key, size)
                with self.lock:
                    if 'rejected' in result:
                        self.rejected.append(result)
                    else:
                        self.accepted[result['id']] = result
            except Exception as error:
                with self.lock:
                    self.errors.append(str(error))
            finally:
                slots.release()

        with ThreadPoolExecutor(max_workers=budget) as executor:
            for index in range(count):
                due = self.started + index / rate
                if self.stop.wait(max(0, due - time.monotonic())):
                    break
                admitted = slots.acquire(timeout=max(0, due + 1 - time.monotonic()))
                if not admitted:
                    with self.lock:
                        self.max_schedule_lag = max(self.max_schedule_lag, time.monotonic() - due)
                        self.errors.append('bounded publisher could not maintain requested pace')
                    break
                executor.submit(publish, f'{prefix}-{index:06d}', due)
        with self.lock:
            self.done = True
            self.finished = time.monotonic()

    def consume_loop(self):
        try:
            while not self.stop.is_set():
                response = self.client.call('PollEvents', {'subscriptionId': self.subscription,
                                                          'deliveryLimit': 32, 'scanLimit': 1024})
                for delivery in response.get('deliveries', []):
                    event = delivery['event']
                    with self.lock:
                        self.deliveries[event['id']] = event
                    self.client.call('AcknowledgeEvent', {'subscriptionId': self.subscription, 'eventId': event['id']})
                    if self.stop.is_set():
                        return
                self.stop.wait(0.05)
        except Exception as error:
            with self.lock:
                self.errors.append(str(error))

    def snapshot(self):
        with self.lock:
            return {'accepted': dict(self.accepted), 'deliveries': dict(self.deliveries),
                    'rejected': list(self.rejected), 'errors': list(self.errors), 'done': self.done,
                    'started': self.started, 'finished': self.finished,
                    'max_schedule_lag_seconds': self.max_schedule_lag}

    def close(self):
        self.stop.set()
        if isinstance(self.publications, PublicationLanes):
            self.publications.close()
        self.publisher.join(10)
        self.consumer.join(10)
        if self.publisher.is_alive() or self.consumer.is_alive():
            raise TimeoutError('workload thread shutdown deadline')


def wait_stopped(pid):
    deadline = time.monotonic() + 10
    while True:
        try:
            state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            # procfs may report ESRCH as well as ENOENT during process exit.
            return
        if state == 'Z':
            return
        if time.monotonic() > deadline:
            raise TimeoutError('agent stop deadline')
        time.sleep(0.05)


def worker_main():
    client = ConnectJsonClient('http://127.0.0.1:8181',
                               read_token_file(Path('/clab/state/client.token')), timeout=30)
    subscription = None
    workload = None
    publications = PublicationLanes()
    try:
        while True:
            line = sys.stdin.readline(16385)
            if not line:
                break
            if len(line) > 16384:
                raise ValueError('worker request bound exceeded')
            try:
                request = json.loads(line)
                action = request['action']
                if action == 'status':
                    result = sample(client)
                elif action == 'subscribe':
                    if subscription is not None:
                        raise ValueError('consumer already initialized')
                    client = DeliveryClient(client)
                    subscription = client.subscribe(b'path-diagnostic', 'mesh.messages', 'demo/playground')['subscriptionId']
                    result = subscription
                elif action == 'publish':
                    result = publish_one(publications, request['key'], request['size'])
                elif action == 'start-workload':
                    if workload is not None:
                        raise ValueError('workload already started')
                    workload = Workload(client, subscription, request['prefix'], request['count'], request['rate'], request['size'], publications)
                    result = {'started': workload.started}
                elif action == 'progress':
                    result = workload.snapshot()
                elif action == 'end-workload':
                    workload.close()
                    result = workload.snapshot()
                elif action == 'poll':
                    result = []
                    response = client.call('PollEvents', {'subscriptionId': subscription,
                                                         'deliveryLimit': 128, 'scanLimit': 1024})
                    for delivery in response.get('deliveries', []):
                        event = delivery['event']
                        result.append(event)
                        client.call('AcknowledgeEvent', {'subscriptionId': subscription, 'eventId': event['id']})
                elif action == 'query-witness':
                    events, _ = client.query_events('mesh.messages', 'demo/playground', request['key'].encode())
                    result = any(event['id'] == request['identity'] for event in events)
                elif action == 'query':
                    result = query_all(client, request['maximum'])
                elif action == 'stop':
                    if workload is not None:
                        workload.close()
                    pid = int(Path('/clab/state/agent.pid').read_text())
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    wait_stopped(pid)
                    result = {'stopped_pid': pid}
                elif action == 'peerless':
                    spec = importlib.util.spec_from_file_location('delivery_agent', LIB + 'delivery-agent.py')
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    argv = module.agent_argv(request['role'])
                    while '--peer' in argv:
                        index = argv.index('--peer')
                        del argv[index:index + 2]
                    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    Path('/clab/state/agent.pid').write_text(str(process.pid))
                    result = {'pid': process.pid, 'argv': argv}
                else:
                    raise ValueError('unknown helper action')
                print(json.dumps({'result': result}, separators=(',', ':')), flush=True)
            except Exception as error:
                print(json.dumps({'error': str(error)}), flush=True)
    finally:
        publications.close()
        if workload is not None:
            workload.close()


class OutageRestoration:
    """Sole network writer from loss application through scheduled restoration.

    configure is bounded Docker IPC, never a worker/application RPC. Joining this
    non-daemon owner precedes every subsequent network change and owned cleanup.
    Even an early controller failure retains the requested outage duration.
    """
    def __init__(self, configure, seconds, record, *, clock=time.monotonic,
                 wait=time.sleep, persist=lambda: None):
        self.configure, self.seconds, self.record = configure, seconds, record
        self.clock, self.wait, self.persist = clock, wait, persist
        self.thread = threading.Thread(target=self._run, name='outage-restoration')

    def arm(self, applied):
        # Called after all replacement attempts, before any slow readback.
        if applied is not None:
            self.record.update(applied_monotonic=applied,
                               restore_target_monotonic=applied + self.seconds)
        self.thread.start()

    def start(self):
        self.record['apply_started_monotonic'] = self.clock()
        try:
            self.configure('outage', on_applied=self.arm)
        except (Exception, KeyboardInterrupt) as error:
            self.record['apply_error'] = str(error) or 'interrupted'
            if self.thread.ident is None:
                self.arm(None)
            raise
        self.check()
        self.require_active()

    def _run(self):
        try:
            target = self.record.get('restore_target_monotonic')
            if target is not None:
                self.wait(max(0, target - self.clock()))
        except Exception as error:
            self.record['restore_error'] = str(error)
        finally:
            self.record['restore_started_monotonic'] = self.clock()
            try:
                self.record['restored_monotonic'] = self.configure('baseline')
            except Exception as error:
                self.record['restore_error'] = str(error)
            try:
                self.persist()
            except Exception as error:
                self.record['evidence_error'] = str(error)

    def check(self):
        errors = [self.record[key] for key in ('apply_error', 'restore_error', 'evidence_error')
                  if key in self.record]
        if errors:
            raise ExecutionError('outage restoration: ' + '; '.join(errors))

    def finish(self):
        # At most the configured remaining outage plus bounded configure calls.
        # No cancellation race, daemon leak, duplicate restore or worker lock.
        if self.thread.ident is not None:
            self.thread.join()

    def require_active(self):
        if ('restore_started_monotonic' in self.record or
                self.clock() >= self.record['restore_target_monotonic']):
            raise ValueError('outage witness not verified before scheduled restore')


def resource_options(config):
    options = []
    if hasattr(config, 'storage_max_items'):
        options += ['--env', f'ASTER_DIAGNOSTIC_STORAGE_ITEMS={config.storage_max_items}',
                    '--env', f'ASTER_DIAGNOSTIC_STORAGE_BYTES={config.storage_mib * 1024 * 1024}']
    if getattr(config, 'cpu_limit', 0):
        options += ['--cpus', str(config.cpu_limit)]
    if getattr(config, 'memory_mib', 0):
        memory = str(config.memory_mib * 1024 * 1024)
        options += ['--memory', memory, '--memory-swap', memory]
    return options


def verify_resource_limits(config, host):
    expected = {'NanoCpus': round(getattr(config, 'cpu_limit', 0) * 1_000_000_000),
                'Memory': getattr(config, 'memory_mib', 0) * 1024 * 1024,
                'MemorySwap': getattr(config, 'memory_mib', 0) * 1024 * 1024}
    if any(host.get(key) != value for key, value in expected.items()):
        raise ExecutionError('resource limit readback mismatch')


def verify_cgroup_limits(config, limits):
    try:
        quota, period = limits['cpu.max'].split()
        if config.cpu_limit and (quota == 'max' or abs(int(quota) / int(period) - config.cpu_limit) > 0.00001):
            raise ValueError('CPU quota')
        if config.memory_mib and (int(limits['memory.max']) != config.memory_mib * 1024 * 1024
                                  or limits['memory.swap.max'] != '0'):
            raise ValueError('memory quota')
    except (KeyError, ValueError, ZeroDivisionError) as error:
        raise ExecutionError('kernel cgroup limit readback mismatch') from error


def run_profile(config, profile, report):
    """Own all containers; never issue a host networking command."""
    roles = tuple(f'node-{chr(97 + i)}' for i in range(getattr(config, 'agents', 2)))
    interfaces = tuple(f'wan{i}' for i in range(1, len(roles) + 1))
    run = _pinned_docker(_run_command)
    docker = shutil.which('docker')
    directory = Path(tempfile.mkdtemp(prefix='aster-diagnostic-'))
    owned = OwnedDocker(docker, directory, _run_command, image=getattr(config, 'image', 'aster-path-delivery:local'))
    workers, nodes, setup = {}, {}, {}
    provision = None
    outage = None
    lab = directory / 'lab'
    lab.mkdir(mode=0o700)
    report.update(profile=profile, status='running', phases=[], samples=[], accepted={},
                  rejected={}, deliveries={}, qdiscs=[], ownership_directory=str(directory))
    start = time.monotonic()

    validate = getattr(config, 'validate_provenance', lambda: None)

    def phase(name):
        if name != 'cleanup':
            validate()
        report['phases'].append({'phase': name, 'elapsed': time.monotonic() - start})
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
        print(json.dumps({'profile': profile, **report['phases'][-1]}), flush=True)

    def command(*args, timeout=30):
        return run([docker, *args], timeout)

    def execute(cid, *args, timeout=30):
        return command('exec', cid, *args, timeout=timeout)

    def cgroup(cid):
        return json.loads(execute(cid, 'python3', '-c',
            "import json,pathlib; p=pathlib.Path('/sys/fs/cgroup'); "
            "print(json.dumps({k:(p/k).read_text().strip() for k in "
            "('cpu.max','memory.max','memory.swap.max','memory.events')}))"))

    def create(role, options, argv, caps=()):
        validate()
        cid = owned.create(role, options, argv, caps)
        if hasattr(config, 'validate_provenance'):
            actual = command('inspect', '--format', '{{.Image}}', cid).decode().strip()
            report.setdefault('all_container_image_ids', {})[role] = actual
            if actual != config.image:
                raise ExecutionError('container image identity mismatch')
        command('start', cid)
        return cid

    def configure(which, *, on_applied=None):
        args = netem_args(which, config.delay_ms, config.jitter_ms, config.loss_percent,
                          config.rate_mbit, config.reorder_percent,
                          bandwidth_kbit=getattr(config, 'bandwidth_kbit', None))
        rows, texts, changes, errors = [], [], [], []
        for interface in interfaces:
            change = {'interface': interface, 'started_monotonic': time.monotonic()}
            changes.append(change)
            try:
                # A zero-delay netem keeps replacement/readback uniform.
                execute(setup['wan'], 'tc', 'qdisc', 'replace', 'dev', interface,
                        'root', 'netem', *(args or ['delay', '0ms']), timeout=5)
                change['applied_monotonic'] = time.monotonic()
            except Exception as error:
                change['error'] = str(error)
                errors.append(interface + ': ' + str(error))
        # Attempt all egresses even if one fails, without retrying a command.
        # Arm restoration BEFORE readback. Use the first egress application as
        # the deadline origin; retain all interface timings in the receipt.
        if on_applied is not None:
            on_applied(None if errors else changes[0]['applied_monotonic'])
        for interface in interfaces:
            try:
                rows.append(json.loads(execute(setup['wan'], 'tc', '-j', '-s', 'qdisc', 'show', 'dev', interface, timeout=5)))
                texts.append(execute(setup['wan'], 'tc', 'qdisc', 'show', 'dev', interface, timeout=5).decode())
            except Exception as error:
                errors.append(interface + ' readback: ' + str(error))
        report['qdiscs'].append({'elapsed': time.monotonic() - start, 'profile': which,
                                 'arguments': args, 'rows': rows, 'text': texts,
                                 'changes': changes, 'errors': errors})
        if errors:
            raise ExecutionError('; '.join(errors))
        if getattr(config, 'bandwidth_kbit', None) is not None:
            verify_bandwidth(rows, config.bandwidth_kbit)
        if which == 'outage' and any('loss 100%' not in text for text in texts):
            raise ValueError('100 percent outage readback failed')
        if which == 'baseline' and any('loss' in text for text in texts):
            raise ValueError('baseline restoration readback still contains loss')
        return changes[-1]['applied_monotonic']

    def consume(action='progress'):
        done = True
        errors = []
        for role, worker in workers.items():
            progress = worker.call(action)
            report['accepted'][role].update(progress['accepted'])
            report['deliveries'][role].update(progress['deliveries'])
            report['rejected'][role] = progress['rejected']
            report.setdefault('workload_timing', {})[role] = {key: progress[key] for key in
                ('done', 'started', 'finished', 'max_schedule_lag_seconds')}
            done = done and progress['done']
            errors.extend(role + ': ' + error for error in progress['errors'])
        if errors:
            raise ValueError('; '.join(errors))
        return done

    def publish(role, key):
        event = workers[role].call('publish', key=key, size=config.payload_bytes)
        if 'rejected' in event:
            report['rejected'][role].append({'key': key, **event})
            return None
        report['accepted'][role][event['id']] = event
        return event['id']

    def sample_all():
        validate()
        report['samples'].append({role: worker.call('status') for role, worker in workers.items()})
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
        print(json.dumps({'profile': profile, 'elapsed': time.monotonic() - start,
                          'accepted': {role: len(events) for role, events in report['accepted'].items()},
                          'rejected': {role: len(events) for role, events in report['rejected'].items()},
                          'delivered': {role: len(events) for role, events in report['deliveries'].items()}}), flush=True)

    def ready(worker):
        deadline = time.monotonic() + 30
        while True:
            try:
                return worker.call('status')
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    previous_alarm = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise ExecutionError('diagnostic profile deadline exceeded')

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(getattr(config, 'duration_seconds', 60) +
                 getattr(config, 'restore_deadline_seconds', 120) + 420)
    try:
        phase('setup')
        wan = create('wan', ['--network', 'none', '--sysctl', 'net.ipv4.ip_forward=1'], ['sleep', '3600'])
        helper_directory = getattr(config, 'helper_directory', Path(__file__).resolve().parent)
        helper_mounts = []
        for name in HELPER_FILES:
            target = 'diagnostic.py' if name == 'aster_path_diagnostic.py' else name
            helper_mounts += ['--volume', str(helper_directory / name) + ':/' + target + ':ro']
        for role in roles:
            (lab / role).mkdir(mode=0o700)
            nodes[role] = create(role, ['--network', 'none', '--volume', str(lab / role) + ':/clab',
                                      *helper_mounts, *resource_options(config)], ['sleep', '3600'])
            if hasattr(config, 'cpu_limit'):
                host = json.loads(command('inspect', '--format', '{{json .HostConfig}}', nodes[role]))
                report.setdefault('resource_limits', {})[role] = {key: host.get(key) for key in ('NanoCpus', 'Memory', 'MemorySwap')}
                verify_resource_limits(config, host)
                limits = cgroup(nodes[role])
                report['resource_limits'][role]['cgroup'] = limits
                verify_cgroup_limits(config, limits)
            report['accepted'][role], report['deliveries'][role], report['rejected'][role] = {}, {}, []
        provision = create('provision', ['--network', 'none', '--volume', str(lab) + ':/lab'],
                           ['sleep', '3600'], ('CHOWN',))
        execute(provision, 'python3', '-c',
                "import os; os.chown('/lab',0,0); "
                f"[os.chown('/lab/'+r,0,0) for r in {roles!r}]")
        execute(provision, LIB + 'delivery-provision.py', str(len(roles)))
        wan_pid = int(command('inspect', '--format', '{{.State.Pid}}', wan))
        if wan_pid <= 1:
            raise ValueError('WAN namespace holder is not running')
        host_netns = os.stat('/proc/self/ns/net').st_ino
        # Daemon resolves the owned running container's namespace bind. No host
        # namespace entry, SYS_ADMIN, privileged container, or host qdisc.
        for segment, (role, cid) in enumerate(nodes.items(), 1):
            setup[role] = create(role + '-setup', ['--network', 'container:' + cid,
                '--volume', f'/proc/{wan_pid}/ns/net:/target:ro'], ['sleep', '3600'], ('NET_ADMIN',))
            if int(command('inspect', '--format', '{{.State.Pid}}', wan)) != wan_pid:
                raise ValueError('WAN namespace identity changed')
            namespace_inodes = json.loads(execute(setup[role], 'python3', '-c',
                "import os,json; print(json.dumps([os.stat('/target').st_ino,os.stat('/proc/self/ns/net').st_ino]))"))
            if len(set([host_netns, *namespace_inodes])) != 3:
                raise ValueError('network namespaces are not isolated')
            execute(setup[role], 'ip', 'link', 'add', 'eth0', 'type', 'veth',
                    'peer', 'name', f'wan{segment}', 'netns', '/target')
            execute(setup[role], LIB + 'delivery-network-init.py', role, str(len(roles)))
        setup['wan'] = create('wan-setup', ['--network', 'container:' + wan], ['sleep', '3600'], ('NET_ADMIN',))
        for segment in range(1, len(roles) + 1):
            execute(setup['wan'], 'ip', 'addr', 'add', f'10.77.{segment}.1/29', 'dev', f'wan{segment}')
            execute(setup['wan'], 'ip', 'link', 'set', f'wan{segment}', 'up')
        configure('baseline' if profile == 'outage' else profile)
        report['production_binary_sha256'] = execute(nodes['node-a'], 'sha256sum', '/usr/local/bin/aster-agent').decode().split()[0]
        report['container_image_ids'] = {role: command('inspect', '--format', '{{.Image}}', cid).decode().strip()
                                         for role, cid in nodes.items()}
        # Bring every peer online before consumer recovery can wait behind a
        # network contact to a not-yet-started endpoint.
        for role, cid in nodes.items():
            command('exec', '--detach', cid, LIB + 'delivery-agent.py', role)
        for role, cid in nodes.items():
            workers[role] = Worker([docker, '--host', 'unix:///var/run/docker.sock', 'exec', '-i', cid,
                                   'env', 'PYTHONPATH=' + LIB, 'python3', '/diagnostic.py', '--worker'])
        for role, worker in workers.items():
            ready(worker)
            execute(nodes[role], LIB + 'delivery-agent.py', 'verify', role)
            worker.call('subscribe')
        execute(wan, LIB + 'delivery-agent.py', 'verify', 'wan')
        report['capabilities'] = 'verified holders and initial agent PIDs'
        sample_all()
        phase('publish-and-continuous-consume')
        publish_start = time.monotonic()
        count = getattr(config, 'events_per_agent', int(config.duration_seconds * config.events_per_second))
        outage_start = None
        restored = None
        witnesses = {}
        next_sample = publish_start
        for role, worker in workers.items():
            worker.call('start-workload', prefix=f'{profile}-{role}', count=count,
                        rate=config.events_per_second, size=config.payload_bytes)
        while True:
            if time.monotonic() - publish_start > config.duration_seconds + 15:
                raise TimeoutError('paced publication completion deadline')
            if profile == 'outage' and outage_start is None and time.monotonic() - publish_start >= config.outage_at_seconds:
                report['outage_restoration'] = {}

                def persist_restoration():
                    (config.output / 'outage-restoration.json').write_text(
                        json.dumps(report['outage_restoration']) + '\n')

                outage = OutageRestoration(configure, config.outage_seconds,
                    report['outage_restoration'], persist=persist_restoration)
                outage.start()
                outage_start = report['outage_restoration']['applied_monotonic']
                report['outage_witness'] = {'ids': witnesses, 'absent_before_restore': False,
                                            'publications': {}}
                phase('confirmed-outage-witness')
                for role in workers:
                    timing = {'started_monotonic': time.monotonic()}
                    report['outage_witness']['publications'][role] = timing
                    try:
                        witnesses[role] = publish(role, f'{profile}-{role}-witness')
                    finally:
                        timing['finished_monotonic'] = time.monotonic()
                    if witnesses[role] is None:
                        raise ValueError('outage witness rejected')
                # Keep workload/unknown-outcome failures primary. The final
                # receipt separately records any missing negative evidence.
                consume()
                outage.require_active()
                for role, identity in witnesses.items():
                    for other in workers:
                        if other == role:
                            continue
                        present = workers[other].call('query-witness', key=f'{profile}-{role}-witness', identity=identity)
                        outage.require_active()
                        if present or identity in report['deliveries'][other]:
                            raise ValueError('outage witness reached peer before restore')
                report['outage_witness'].update(absent_before_restore=True,
                    verified_monotonic=time.monotonic())
            if outage is not None:
                outage.check()
                restored = report['outage_restoration'].get('restored_monotonic')
            done = consume()
            if time.monotonic() >= next_sample:
                sample_all()
                next_sample = time.monotonic() + config.sample_seconds
            if done:
                if outage is not None:
                    outage.finish()
                    outage.check()
                    restored = report['outage_restoration'].get('restored_monotonic')
                break
            time.sleep(0.25)
        report['publish_elapsed_seconds'] = time.monotonic() - publish_start
        for role in workers:
            expected_attempts = count + (1 if role in witnesses else 0)
            if len(report['accepted'][role]) + len(report['rejected'][role]) != expected_attempts:
                raise ValueError('publication attempt accounting mismatch')
        if profile == 'outage' and restored is None:
            raise ValueError('workload ended before outage restore')
        if outage is not None:
            outage.finish()
            outage.check()
        phase('drain')
        deadline = (restored or time.monotonic()) + config.restore_deadline_seconds
        while True:
            consume()
            complete = True
            for other in workers:
                received_all = True
                for role in workers:
                    if other == role:
                        continue
                    try:
                        verify_events(report['accepted'][role], report['deliveries'][other], deadline=deadline)
                    except ValueError:
                        complete = received_all = False
                if received_all:
                    report.setdefault('delivery_timing', {}).setdefault(other, {
                        'observed_monotonic': time.monotonic(),
                        'since_publication_start_seconds': time.monotonic() - publish_start,
                        'since_restoration_seconds': time.monotonic() - restored if restored else None})
            if complete:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('admitted Events not delivered before deadline')
            if time.monotonic() >= next_sample:
                sample_all()
                next_sample = time.monotonic() + config.sample_seconds
            time.sleep(0.1)
        report['restore_delivery_seconds'] = time.monotonic() - restored if restored else None
        sample_all()
        report['final_qdisc_stats'] = {interface: json.loads(execute(setup['wan'], 'tc', '-j', '-s',
            'qdisc', 'show', 'dev', interface)) for interface in interfaces}
        phase('stop-all')
        # Drain observes deliveries before their acknowledgement RPC returns.
        # Join all workloads and check their final errors before reopening.
        consume('end-workload')
        for worker in workers.values():
            worker.call('stop')
        # Keep all WAN egresses completely cut across peerless reopen too.
        configure('outage')
        phase('peerless-reopen')
        expected = {identity: event for events in report['accepted'].values() for identity, event in events.items()}
        report['peerless'] = {}
        for role, worker in workers.items():
            restart = worker.call('peerless', role=role)
            ready(worker)
            execute(nodes[role], LIB + 'delivery-agent.py', 'verify', role)
            actual = worker.call('query', maximum=(count + 1) * len(roles), timeout=180)
            report['peerless'][role] = {'restart': restart, 'exact_events': verify_events(expected, actual, exact=True)}
        sample_all()
        validate()
        report['status'] = 'verified' if hasattr(config, 'validate_provenance') else 'pass'
    except (Exception, KeyboardInterrupt) as error:
        report['status'] = 'fail'
        report['error'] = str(error) or 'interrupted'
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
        cleanup_errors = []
        if outage is not None:
            # SIGTERM/interrupt during application IPC cannot bypass restoration.
            # Defer further interrupts until the bounded network owner is joined.
            previous_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
            previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                outage.finish()
                witness = report.get('outage_witness')
                if witness is not None and not witness['absent_before_restore']:
                    witness['error'] = 'outage witness not verified before scheduled restore'
                restored_at = report['outage_restoration'].get('restored_monotonic')
                if restored_at is not None:
                    report['phases'].append({'phase': 'restored', 'elapsed': restored_at - start})
                    report['phases'].sort(key=lambda row: row['elapsed'])
                try:
                    outage.check()
                except Exception as error:
                    report['restoration_error'] = str(error)
                    report['status'] = 'fail'
                    report.setdefault('error', str(error))
            finally:
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
        try:
            phase('cleanup')
        except OSError:
            cleanup_errors.append('progress-output')
        for worker in workers.values():
            try:
                worker.call('stop')
            except Exception:
                pass
            try:
                worker.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        # CHOWN-only provisioning helper reclaims only its private bind tree.
        # No host privilege or additional daemon capability is needed.
        if provision is not None:
            try:
                execute(provision, 'python3', '-c',
                        "import os,pathlib\n"
                        "def purge(p):\n"
                        " os.chown(p,0,0,follow_symlinks=False)\n"
                        " if p.is_dir() and not p.is_symlink():\n"
                        "  os.chmod(p,0o700)\n"
                        "  for c in p.iterdir(): purge(c)\n"
                        "  p.rmdir()\n"
                        " else: p.unlink()\n"
                        "p=pathlib.Path('/lab')\n"
                        "os.chown(p,0,0); os.chmod(p,0o700)\n"
                        "for c in p.iterdir(): purge(c)\n"
                        f"os.chown(p,{os.getuid()},{os.getgid()})\n")
            except Exception:
                cleanup_errors.append('credential-cleanup')
        report['container_exit_state'] = {}
        if hasattr(config, 'cpu_limit'):
            for role, cid in nodes.items():
                try:
                    state = json.loads(command('inspect', '--format', '{{json .State}}', cid))
                    report['container_exit_state'][role] = state
                    if state.get('Running'):
                        state['cgroup'] = cgroup(cid)
                        memory_events = dict(line.split() for line in state['cgroup']['memory.events'].splitlines())
                        if int(memory_events.get('oom_kill', 0)):
                            report.update(status='fail', oom_error=role + ': cgroup OOM kill')
                    if state.get('OOMKilled') or state.get('ExitCode', 0) != 0:
                        report['status'] = 'fail'
                except Exception as error:
                    cleanup_errors.append('exit-state: ' + str(error))
        cleanup_errors.extend(owned.cleanup())
        if not cleanup_errors:
            try:
                shutil.rmtree(directory)
            except OSError:
                cleanup_errors.append('directory-cleanup')
        report['cleanup_errors'] = cleanup_errors
        report['elapsed_seconds'] = time.monotonic() - start
        if cleanup_errors:
            report['status'] = 'fail'
        try:
            validate()
        except Exception as error:
            report.update(status='fail', provenance_error=str(error))
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
    return report


def parse_config(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--image', default='aster-path-delivery:local')
    parser.add_argument('--build-kind', choices=['canonical-release', 'local-debug', 'local-release'], default='canonical-release')
    parser.add_argument('--profiles', nargs='+', choices=['baseline', 'impaired', 'reorder', 'outage'],
                        default=['baseline', 'impaired', 'reorder', 'outage'])
    parser.add_argument('--events-per-agent', type=int)
    parser.add_argument('--cpu-limit', type=float, default=0)
    bounds = {'agents': (2, 2, 20), 'memory-mib': (0, 0, 16384),
              'storage-max-items': (10000, 4161, 1000000), 'storage-mib': (64, 64, 4096),
              'duration-seconds': (60, 1, 1800), 'events-per-second': (10, 1, 100),
              'payload-bytes': (1024, 1, 4096), 'delay-ms': (40, 1, 1000),
              'jitter-ms': (5, 0, 100), 'loss-percent': (1, 0, 50),
              'rate-mbit': (100, 1, 1000), 'reorder-percent': (10, 0, 100),
              'outage-seconds': (10, 1, 60), 'outage-at-seconds': (20, 0, 120),
              'restore-deadline-seconds': (120, 1, 600), 'sample-seconds': (5, 1, 30)}
    for name, (default, _, _) in bounds.items():
        parser.add_argument('--' + name, type=int, default=default)
    parser.add_argument('--bandwidth-kbit', type=int,
                        help='Bandwidth per WAN egress in kbit/s (0 = no limit; omitted = profile default); overrides --rate-mbit')
    config = parser.parse_args(argv)
    if config.bandwidth_kbit is not None and not 0 <= config.bandwidth_kbit <= 1000000:
        # Same upper bound as the existing 1000-mbit netem setting.
        parser.error('bandwidth-kbit must be an integer in 0..1000000')
    if config.worker:
        return config
    if config.output is None:
        parser.error('--output is required')
    for name, (_, low, high) in bounds.items():
        if not low <= getattr(config, name.replace('-', '_')) <= high:
            parser.error(name + ' outside supported bounds')
    if not (config.cpu_limit == 0 or 0.1 <= config.cpu_limit <= 64):
        parser.error('cpu-limit must be 0 (unrestricted) or 0.1..64')
    if config.memory_mib != 0 and config.memory_mib < 64:
        parser.error('memory-mib must be 0 (unrestricted) or 64..16384')
    if config.events_per_agent is None:
        config.events_per_agent = config.duration_seconds * config.events_per_second
    else:
        config.duration_seconds = (config.events_per_agent + config.events_per_second - 1) // config.events_per_second
    if not 1 <= config.events_per_agent <= 10000 or config.duration_seconds > 1800:
        parser.error('workload must contain 1..10000 Events per agent and take at most 1800 seconds')
    if config.agents ** 2 * (config.events_per_agent + 1) * (config.payload_bytes * 3 + 1024) > 256 * 1024 * 1024:
        parser.error('combined workload exceeds 256 MiB receipt/IPC budget')
    if len(set(config.profiles)) != len(config.profiles):
        parser.error('duplicate profiles')
    if len(config.profiles) * (config.duration_seconds + config.restore_deadline_seconds) > 2400:
        parser.error('combined workload exceeds 2400-second campaign budget')
    if 'outage' in config.profiles and config.outage_at_seconds + config.outage_seconds >= config.duration_seconds:
        parser.error('outage must finish within publication window')
    return config


def main():
    config = parse_config()
    if config.worker:
        worker_main()
        return 0
    os.umask(0o077)

    def interrupted(_signum, _frame):
        raise ExecutionError('diagnostic terminated')

    signal.signal(signal.SIGTERM, interrupted)
    config.output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'aster-path-diagnostic/v1', 'status': 'running',
              'configuration': {k: v for k, v in vars(config).items() if k not in ('worker', 'output')},
              'profiles': [], 'limitation': 'one-host Docker; no physical or production acceptance claim'}
    run = _pinned_docker(_run_command)
    root = Path(__file__).resolve().parent.parent
    try:
        identity = source_identity(root)
        report.update(identity)
        report['helper_sha256'] = identity['helper_files_sha256']['aster_path_diagnostic.py']
        report['publisher_helper_sha256'] = identity['helper_files_sha256']['aster_mesh_playground.py']
        report['image_id'] = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', config.image], 5).decode().strip()
        if re.fullmatch(r'sha256:[0-9a-f]{64}', report['image_id']) is None:
            raise ExecutionError('invalid immutable image ID')
        config.image = report['image_id']
        with tempfile.TemporaryDirectory(prefix='aster-diagnostic-helpers-') as helpers:
            config.helper_directory = Path(helpers)
            for name in HELPER_FILES:
                destination = config.helper_directory / name
                destination.write_bytes((root / 'tools' / name).read_bytes())
                destination.chmod(0o444)

            def validate_provenance():
                if source_identity(root) != identity:
                    raise ExecutionError('source/helper drift during diagnostic')
                for name, digest in identity['helper_files_sha256'].items():
                    if hashlib.sha256((config.helper_directory / name).read_bytes()).hexdigest() != digest:
                        raise ExecutionError('frozen helper drift during diagnostic')

            config.validate_provenance = validate_provenance
            validate_provenance()
            for profile in config.profiles:
                validate_provenance()
                row = {}
                report['profiles'].append(row)
                run_profile(config, profile, row)
                validate_provenance()
                (config.output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
            # No profile publishes PASS until the whole campaign's final identity
            # check. Failed campaigns retain individually verified (not PASS) rows.
            validate_provenance()
            report['status'] = 'pass' if all(row['status'] == 'verified' for row in report['profiles']) else 'fail'
            if report['status'] == 'pass':
                for row in report['profiles']:
                    row['status'] = 'pass'
                    (config.output / (row['profile'] + '.json')).write_text(json.dumps(row) + '\n')
    except Exception as error:
        report.update(status='fail', error=str(error))
    finally:
        (config.output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'receipt': str(config.output / 'receipt.json')}))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
