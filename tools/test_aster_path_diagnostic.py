#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
import unittest
import sys
import argparse
from pathlib import Path
import tempfile
from unittest.mock import patch
import aster_path_diagnostic as diagnostic


class BandwidthInputTests(unittest.TestCase):
    def test_readback_uses_tc_bytes_per_second_and_fails_closed(self):
        def rows(rate):
            return [[{'kind': 'netem', 'root': True, 'options': {'rate': {'rate': rate}}}]]
        diagnostic.verify_bandwidth(rows(375), 3)
        diagnostic.verify_bandwidth(rows(125000000), 1000000)
        diagnostic.verify_bandwidth([[{'kind': 'netem', 'root': True, 'options': {}}]], 0)
        for actual, expected in [(rows(3), 3), (rows(375), 0), (rows(0), 3), ([], 3), ([[]], 0)]:
            with self.subTest(actual=actual), self.assertRaisesRegex(diagnostic.ExecutionError, 'bandwidth readback'):
                diagnostic.verify_bandwidth(actual, expected)

    def test_override_applies_to_every_profile_and_zero_removes_rate(self):
        defaults = {
            'baseline': [], 'outage': ['loss', '100%'],
            'impaired': ['limit', '1000', 'delay', '40ms', '5ms', 'loss', '1%', 'rate', '100mbit'],
            'reorder': ['limit', '1000', 'delay', '40ms', '5ms', 'loss', '1%', 'rate', '100mbit', 'reorder', '10%'],
        }
        for profile, expected in defaults.items():
            with self.subTest(profile=profile):
                self.assertEqual(diagnostic.netem_args(profile, 40, 5, 1, 100, 10), expected)
                uncapped = expected.copy()
                if 'rate' in uncapped:
                    index = uncapped.index('rate')
                    del uncapped[index:index + 2]
                self.assertEqual(diagnostic.netem_args(profile, 40, 5, 1, 100, 10, bandwidth_kbit=0), uncapped)
                self.assertEqual(diagnostic.netem_args(profile, 40, 5, 1, 100, 10, bandwidth_kbit=3), uncapped + ['rate', '3kbit'])

    def test_optional_override_preserves_defaults_and_accepts_integer_kbit(self):
        base = ['--output', 'unused', '--profiles', 'baseline']
        self.assertIsNone(diagnostic.parse_config(base).bandwidth_kbit)
        for value in (0, 1, 3, 1000000):
            config = diagnostic.parse_config(base + ['--bandwidth-kbit', str(value)])
            self.assertEqual(config.bandwidth_kbit, value)
        for value in ('-1', '1000001', '3.5', 'nan', '$(id)', ''):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                diagnostic.parse_config(base + ['--bandwidth-kbit', value])
        self.assertEqual(diagnostic.parse_config(base + ['--rate-mbit', '20']).rate_mbit, 20)


class StorageInputTests(unittest.TestCase):
    def test_storage_inputs_reach_initial_and_peerless_agent_argv(self):
        import importlib.util
        config = diagnostic.parse_config(['--output', 'unused', '--profiles', 'baseline',
            '--storage-max-items', '50000', '--storage-mib', '512'])
        self.assertIn('ASTER_DIAGNOSTIC_STORAGE_ITEMS=50000', diagnostic.resource_options(config))
        self.assertIn('ASTER_DIAGNOSTIC_STORAGE_BYTES=536870912', diagnostic.resource_options(config))
        spec = importlib.util.spec_from_file_location('agent', Path(__file__).resolve().parents[1] / 'docker/path-lab/delivery-agent.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'peer').write_text('a' * 64 + '@10.77.2.2:4433=' + 'b' * 64)
            with patch.dict(module.os.environ, {'ASTER_DIAGNOSTIC_STORAGE_ITEMS': '50000', 'ASTER_DIAGNOSTIC_STORAGE_BYTES': '536870912'}):
                argv = module.agent_argv('node-a', state)
                self.assertEqual(argv[argv.index('--storage-max-items') + 1], '50000')
                self.assertEqual(argv[argv.index('--storage-max-payload-bytes') + 1], '536870912')
            with patch.dict(module.os.environ, {'ASTER_DIAGNOSTIC_STORAGE_ITEMS': '$(bad)', 'ASTER_DIAGNOSTIC_STORAGE_BYTES': '536870912'}):
                with self.assertRaises(ValueError):
                    module.agent_argv('node-a', state)
        for flag, value in [('--storage-max-items', '4160'), ('--storage-max-items', '1000001'), ('--storage-mib', '63'), ('--storage-mib', '4097')]:
            with self.assertRaises(SystemExit):
                diagnostic.parse_config(['--output', 'unused', flag, value])


class DeliveryOwnershipTests(unittest.TestCase):
    def test_consumer_recovers_its_own_session_and_contextualizes_mutations(self):
        calls = []
        rpc = diagnostic.ConnectJsonClient('http://127.0.0.1:8181', 'a' * 64)
        def call(method, request):
            calls.append((method, request))
            if method == 'BeginEventPublicationSession':
                return {'session': '1', 'snapshotRevision': '7'}
            return {'subscriptionId': diagnostic.base64.b64encode(b's' * 32).decode()}
        rpc.call = call
        consumer = diagnostic.DeliveryClient(rpc)
        consumer.subscribe(b'key', 'mesh.messages', 'demo/playground')
        consumer.call('PollEvents', {'subscriptionId': 'sub'})
        consumer.call('AcknowledgeEvent', {'subscriptionId': 'sub', 'eventId': 'event'})
        self.assertEqual([method for method, _ in calls[:2]], ['BeginEventPublicationSession', 'CompleteEventPublicationRecovery'])
        for _, request in calls[2:]:
            self.assertEqual(request['client'], {'clientId': diagnostic.base64.b64encode(b'path-diagnostic-consumer').decode(), 'session': '1'})
        self.assertEqual(calls[1][1]['snapshotRevision'], '7')


class NumberedPublicationTests(unittest.TestCase):
    def test_lost_response_recovers_original_intent_without_new_publication(self):
        calls = []
        publisher = diagnostic.DiagnosticPublisher.__new__(diagnostic.DiagnosticPublisher)
        def run(action, options=(), payload=None, **kwargs):
            calls.append(action)
            if action == 'publish':
                raise diagnostic.PublicationRpcError('lost response')
            if action == 'publication-recover':
                return {'operations': [{'operationSequence': '1', 'state': 'committed',
                                        'result': {'operationSequence': '1', 'receipt': {'eventId': 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='}}}]}
            if action == 'publication-show':
                return {'logicalKey': 'aw==', 'payload': 'cA=='}
        publisher._run = run
        self.assertEqual(publisher.publish_event(b'k', b'p')['id'], 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=')
        self.assertEqual(calls.count('publish'), 1)
        self.assertIn('publication-ack', calls)

    def test_malformed_success_recovers_before_acknowledging(self):
        calls = []
        publisher = diagnostic.DiagnosticPublisher.__new__(diagnostic.DiagnosticPublisher)
        identity = diagnostic.base64.b64encode(b'x' * 32).decode()
        result = {'operationSequence': '1', 'receipt': {'eventId': identity}}
        def run(action, options=(), payload=None, **kwargs):
            calls.append(action)
            if action == 'publish':
                return {'result': {'operationSequence': '1', 'receipt': {'eventId': 'bad'}}, 'inserted': True}
            if action == 'publication-recover':
                return {'operations': [{'operationSequence': '1', 'state': 'pending'}]}
            if action == 'publication-show':
                return {'logicalKey': 'aw==', 'payload': 'cA=='}
            if action == 'publication-retry':
                self.assertEqual(options, ['--sequence', '1'])
                return result
        publisher._run = run
        self.assertEqual(publisher.publish_event(b'k', b'p')['id'], identity)
        self.assertEqual(calls, ['publish', 'publication-recover', 'publication-show', 'publication-retry', 'publication-ack'])

    def test_unresolved_failure_is_unknown_not_capacity_rejection(self):
        publisher = diagnostic.DiagnosticPublisher.__new__(diagnostic.DiagnosticPublisher)
        publisher._run = lambda *a, **kw: (_ for _ in ()).throw(diagnostic.PublicationRpcError('unavailable'))
        with self.assertRaisesRegex(diagnostic.RpcError, 'unknown'):
            publisher.publish_event(b'k', b'p')


class OutageRestorationTests(unittest.TestCase):
    def test_restores_while_controller_is_blocked(self):
        import threading
        now = [100.0]
        waiting = threading.Event()
        advance = threading.Event()
        restored = threading.Event()
        calls = []
        record = {}

        def configure(profile, *, on_applied=None):
            if on_applied is not None:
                on_applied(100)
            calls.append(profile)
            if profile == 'baseline':
                restored.set()
            return now[0]

        def wait(seconds):
            self.assertEqual(seconds, 10)
            waiting.set()
            self.assertTrue(advance.wait(2))
            now[0] = 110.0

        outage = diagnostic.OutageRestoration(configure, 10, record,
            clock=lambda: now[0], wait=wait)
        outage.start()
        self.assertTrue(waiting.wait(2))
        # The controller cannot proceed until its witness RPC returns. The
        # restoration thread must not depend on that RPC or worker IPC locks.
        advance.set()
        self.assertTrue(restored.wait(2))
        outage.finish()
        self.assertEqual(calls, ['outage', 'baseline'])
        self.assertEqual(record['applied_monotonic'], 100)
        self.assertEqual(record['restore_target_monotonic'], 110)
        self.assertEqual(record['restored_monotonic'], 110)
        self.assertFalse(outage.thread.is_alive())


    def test_early_cleanup_joins_timer_without_duplicate_restore(self):
        import threading
        entered, advance, restored = (threading.Event() for _ in range(3))
        calls, record = [], {}
        now = [100.0]

        def configure(profile, *, on_applied=None):
            if on_applied is not None:
                on_applied(100)
            calls.append(profile)
            if profile == 'baseline':
                restored.set()
            return now[0]

        def wait(seconds):
            entered.set()
            self.assertTrue(advance.wait(2))
            now[0] += seconds

        outage = diagnostic.OutageRestoration(configure, 10, record,
            clock=lambda: now[0], wait=wait)
        outage.start()
        self.assertTrue(entered.wait(2))
        cleanup = threading.Thread(target=outage.finish)
        cleanup.start()
        self.assertFalse(restored.is_set())
        advance.set()
        cleanup.join(2)
        outage.finish()
        self.assertFalse(cleanup.is_alive())
        self.assertFalse(outage.thread.is_alive())
        self.assertEqual(calls, ['outage', 'baseline'])
        self.assertEqual(record['restored_monotonic'], 110)

    def test_restore_failure_is_retained_and_owner_reaped(self):
        record = {}
        def configure(profile, *, on_applied=None):
            if on_applied is not None:
                on_applied(100)
            if profile == 'baseline':
                raise ValueError('restore command failed')
            return 100
        outage = diagnostic.OutageRestoration(configure, 10, record,
            clock=lambda: 100, wait=lambda _: None)
        try:
            outage.start()
        except diagnostic.ExecutionError:
            pass  # Fast completion may publish the error before start returns.
        outage.finish()
        with self.assertRaisesRegex(diagnostic.ExecutionError, 'restore command failed'):
            outage.check()
        self.assertNotIn('restored_monotonic', record)
        self.assertFalse(outage.thread.is_alive())

    def test_partial_apply_failure_still_restores_without_waiting(self):
        calls, record = [], {}
        def configure(profile, *, on_applied=None):
            calls.append(profile)
            if profile == 'outage':
                raise ValueError('partial apply failed')
            return 100
        outage = diagnostic.OutageRestoration(configure, 10, record,
            clock=lambda: 100, wait=lambda _: self.fail('must not schedule failed apply'))
        with self.assertRaisesRegex(ValueError, 'partial apply failed'):
            outage.start()
        outage.finish()
        self.assertEqual(calls, ['outage', 'baseline'])
        self.assertNotIn('restore_target_monotonic', record)
        self.assertEqual(record['restored_monotonic'], 100)


class OutageProfileTests(unittest.TestCase):
    """Real controller/restorer; deterministic clock and bounded fake Docker/IPC."""
    def test_five_agents_all_publish_receive_and_reopen(self):
        result, changes, _ = self.run_outage(agents=5)
        self.assertEqual(result['status'], 'pass', result.get('error'))
        self.assertEqual(len(result['peerless']), 5)
        self.assertEqual(set(result['delivery_timing']), set(result['peerless']))
        self.assertEqual({row['exact_events'] for row in result['peerless'].values()}, {3005})
        self.assertEqual({interface for interface, _, _ in changes}, {f'wan{i}' for i in range(1, 6)})

    def run_outage(self, failure=None, agents=2):
        import threading
        import json
        import os
        condition = threading.Condition()
        now = [100.0]
        restored = threading.Event()
        applying = threading.Event()
        actions = []
        qdiscs = {f'wan{i}': False for i in range(1, agents + 1)}
        changes = []
        events = {f'node-{chr(97 + i)}': {} for i in range(agents)}
        agent_started = set()
        original = diagnostic.OutageRestoration
        record = {}

        def clock():
            with condition:
                return now[0]

        def advance(seconds):
            with condition:
                now[0] += seconds
                condition.notify_all()
            if applying.is_set() and now[0] >= record.get('restore_target_monotonic', float('inf')):
                self.assertTrue(restored.wait(2))

        def wait(seconds):
            with condition:
                target = record['restore_target_monotonic']
                self.assertTrue(condition.wait_for(lambda: now[0] >= target, timeout=2))

        def restorer(configure, seconds, evidence, **kwargs):
            nonlocal record
            record = evidence
            owner = original(configure, seconds, evidence, clock=clock, wait=wait, **kwargs)
            if failure == 'terminated':
                finish = owner.finish
                def finish_after_clock_advance():
                    advance(max(0, record['restore_target_monotonic'] - clock()))
                    finish()
                owner.finish = finish_after_clock_advance
            return owner

        class Owned:
            def __init__(self, *args, **kwargs):
                pass
            def create(self, role, *args):
                return role
            def cleanup(self):
                actions.append('cleanup')
                if applying.is_set():
                    self_test.assertTrue(restored.is_set())
                return []

        self_test = self
        class Worker:
            def __init__(self, argv):
                self.role = argv[argv.index('-i') + 1]
            def call(self, action, **kwargs):
                actions.append(action)
                if action == 'subscribe':
                    self_test.assertEqual(agent_started, set(events), 'all peers must start before consumer recovery')
                if action == 'start-workload':
                    for i in range(kwargs['count']):
                        identity = self.role + str(i)
                        events[self.role][identity] = {'id': identity, 'logicalKey': identity, 'payload': 'x'}
                if action == 'publish':
                    if failure == 'terminated':
                        os.kill(os.getpid(), diagnostic.signal.SIGTERM)
                    if failure in ('blocked-witness', 'blocked-slot'):
                        advance(10)
                        self_test.assertTrue(restored.wait(2))
                    if failure == 'publish-error':
                        advance(10)
                        raise ValueError('numbered publication outcome unknown')
                    event = {'id': kwargs['key'], 'logicalKey': kwargs['key'], 'payload': 'x'}
                    events[self.role][event['id']] = event
                    return event
                if action == 'query-witness':
                    return False
                if action in ('progress', 'end-workload'):
                    if applying.is_set() and failure in ('consume-error', 'double-error'):
                        # Release the timer while unwinding the main controller.
                        advance(10)
                        raise ValueError('PollEvents HTTP 504')
                    errors = ['bounded publisher could not maintain requested pace'] if applying.is_set() and failure in ('slot-limit', 'blocked-slot') else []
                    if errors:
                        advance(10)
                    return {'accepted': dict(events[self.role]), 'deliveries': {k: v for rows in events.values() for k, v in rows.items()} if restored.is_set() and failure != 'delivery-timeout' else {},
                            'rejected': [], 'errors': errors, 'done': restored.is_set(),
                            'started': 100, 'finished': clock(), 'max_schedule_lag_seconds': 0}
                if action == 'query':
                    return {k: v for rows in events.values() for k, v in rows.items()}
                return {}
            def close(self):
                pass

        def command(argv, timeout):
            if '--detach' in argv:
                agent_started.add(argv[argv.index('--detach') + 1])
            if 'inspect' in argv:
                return b'123'
            if any("os.stat('/target')" in arg for arg in argv):
                inode = os.stat('/proc/self/ns/net').st_ino
                return json.dumps([inode + 1, inode + 2]).encode()
            if 'sha256sum' in argv:
                return b'test-hash'
            if 'tc' in argv:
                interface = argv[argv.index('dev') + 1]
                if 'replace' in argv:
                    is_loss = '100%' in argv
                    changes.append((interface, is_loss, clock()))
                    if not is_loss and applying.is_set() and failure == 'double-error' and interface == 'wan1':
                        raise ValueError('injected restore failure')
                    qdiscs[interface] = is_loss
                    if is_loss and failure == 'partial-apply' and interface == 'wan2':
                        raise ValueError('injected partial application failure')
                    if is_loss:
                        applying.set()
                    elif applying.is_set() and (not any(qdiscs.values()) or failure == 'double-error'):
                        restored.set()
                elif applying.is_set() and not restored.is_set() and failure == 'slow-readback':
                    # Each individual read stays within its five-second bound.
                    # The third read crosses the outage deadline while blocked.
                    if clock() == 108:
                        advance(2)
                        self_test.assertTrue(restored.wait(2), 'restore waited for readback')
                        advance(2)
                    else:
                        advance(4)
                    if clock() >= 110:
                        self_test.assertTrue(restored.wait(2), 'restore waited for readback')
                return b'[]' if '-j' in argv else (b'loss 100%' if qdiscs[interface] else b'delay 0ms')
            return b''

        with tempfile.TemporaryDirectory() as directory:
            config = argparse.Namespace(output=Path(directory), agents=agents, duration_seconds=60,
                events_per_second=10, payload_bytes=1024, delay_ms=40, jitter_ms=5,
                loss_percent=1, rate_mbit=100, reorder_percent=10, outage_at_seconds=0,
                outage_seconds=10, restore_deadline_seconds=120, sample_seconds=5)
            with patch.object(diagnostic, 'OwnedDocker', Owned), patch.object(diagnostic, 'Worker', Worker), \
                    patch.object(diagnostic, '_pinned_docker', return_value=command), \
                    patch.object(diagnostic, 'OutageRestoration', side_effect=restorer), \
                    patch.object(diagnostic.time, 'monotonic', side_effect=clock), \
                    patch.object(diagnostic.time, 'sleep', side_effect=advance):
                def terminate(_signum, _frame):
                    raise diagnostic.ExecutionError('diagnostic terminated')
                previous = diagnostic.signal.signal(diagnostic.signal.SIGTERM, terminate)
                try:
                    result = diagnostic.run_profile(config, 'outage', {})
                    self.assertIs(diagnostic.signal.getsignal(diagnostic.signal.SIGTERM), terminate)
                finally:
                    diagnostic.signal.signal(diagnostic.signal.SIGTERM, previous)
        self.assertFalse(any(t.name == 'outage-restoration' for t in threading.enumerate()))
        return result, changes, actions

    def test_partial_loss_replacement_failure_restores_both_interfaces(self):
        result, changes, actions = self.run_outage('partial-apply')
        self.assertEqual(result['status'], 'fail')
        self.assertIn('injected partial application failure', result['error'])
        self.assertEqual([interface for interface, loss, _ in changes if loss], ['wan1', 'wan2'])
        self.assertEqual([interface for interface, loss, _ in changes if not loss], ['wan1', 'wan2'] * 2)
        self.assertNotIn('publish', actions)
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 100)

    def test_slow_individual_readbacks_cannot_defer_both_restore_commands(self):
        result, changes, actions = self.run_outage('slow-readback')
        self.assertEqual(result['status'], 'fail')
        self.assertNotIn('publish', actions)
        self.assertEqual([t for _, loss, t in changes if not loss], [100, 100, 110, 110])
        self.assertNotIn('restore waited for readback', result.get('error', ''))
        self.assertEqual(result['outage_restoration']['restore_target_monotonic'], 110)

    def test_blocked_witness_does_not_delay_restore_or_count_as_negative_evidence(self):
        result, changes, _ = self.run_outage('blocked-witness')
        self.assertEqual(result['status'], 'fail')
        self.assertIn('not verified before scheduled restore', result['error'])
        self.assertEqual([t for _, loss, t in changes if not loss], [100, 100, 110, 110])
        self.assertFalse(result['outage_witness']['absent_before_restore'])


    def test_late_witness_evidence_error_is_retained_alongside_workload_failure(self):
        result, _, _ = self.run_outage('blocked-slot')
        self.assertIn('bounded publisher could not maintain requested pace', result['error'])
        self.assertIn('not verified before scheduled restore', result['outage_witness']['error'])
        self.assertFalse(result['outage_witness']['absent_before_restore'])

    def test_consume_exception_still_restores_and_remains_failure(self):
        result, changes, _ = self.run_outage('consume-error')
        self.assertEqual(result['status'], 'fail')
        self.assertIn('PollEvents HTTP 504', result['error'])
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 110)

    def test_slot_limit_still_restores_and_remains_failure(self):
        result, changes, _ = self.run_outage('slot-limit')
        self.assertEqual(result['status'], 'fail')
        self.assertIn('bounded publisher could not maintain requested pace', result['error'])
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 110)

    def test_sigterm_restores_before_owned_cleanup(self):
        result, changes, actions = self.run_outage('terminated')
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['error'], 'diagnostic terminated')
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 110)
        self.assertEqual(actions.count('cleanup'), 1)

    def test_unknown_publication_failure_is_not_reclassified(self):
        result, _, _ = self.run_outage('publish-error')
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['error'], 'numbered publication outcome unknown')
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 110)

    def test_restoration_error_does_not_mask_original_error_and_attempts_both_egresses(self):
        result, changes, _ = self.run_outage('double-error')
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['error'], 'PollEvents HTTP 504')
        self.assertIn('injected restore failure', result['restoration_error'])
        self.assertNotIn('restored_monotonic', result['outage_restoration'])
        self.assertEqual([interface for interface, loss, t in changes if not loss and t == 110], ['wan1', 'wan2'])

    def test_delivery_deadline_remains_120_seconds_after_actual_restore(self):
        result, _, _ = self.run_outage('delivery-timeout')
        self.assertEqual(result['status'], 'fail')
        self.assertIn('admitted Events not delivered before deadline', result['error'])
        self.assertAlmostEqual(result['elapsed_seconds'], 130, delta=0.11)

    def test_normal_outage_has_negative_witness_and_exact_peerless_inventory(self):
        result, changes, actions = self.run_outage()
        self.assertEqual(result['status'], 'pass', result.get('error'))
        self.assertTrue(result['outage_witness']['absent_before_restore'])
        self.assertLess(result['outage_witness']['verified_monotonic'], 110)
        self.assertEqual(result['outage_restoration']['restored_monotonic'], 110)
        self.assertEqual([row['exact_events'] for row in result['peerless'].values()], [1202, 1202])
        self.assertIn('end-workload', actions)


class ScaleConfigurationTests(unittest.TestCase):
    def test_explicit_count_drives_duration_and_retains_legacy_defaults(self):
        config = diagnostic.parse_config(['--output', 'unused', '--agents', '5', '--events-per-agent', '1000', '--profiles', 'baseline'])
        self.assertEqual((config.agents, config.events_per_agent, config.duration_seconds), (5, 1000, 100))
        config = diagnostic.parse_config(['--output', 'unused'])
        self.assertEqual((config.agents, config.events_per_agent, config.duration_seconds), (2, 600, 60))
        self.assertEqual(config.profiles, ['baseline', 'impaired', 'reorder', 'outage'])
        config = diagnostic.parse_config(['--output', 'unused', '--events-per-agent', '10000', '--profiles', 'baseline'])
        self.assertEqual(config.events_per_agent, 10000)

    def test_invalid_or_excessive_inputs_fail_before_docker(self):
        for args in (['--agents', '21'], ['--agents', '1'], ['--events-per-agent', '0'],
                     ['--cpu-limit', 'nan'], ['--cpu-limit', '-1'], ['--memory-mib', '1'],
                     ['--events-per-agent', '10000', '--agents', '20'],
                     ['--events-per-agent', '10000'], ['--events-per-second', '0']):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                diagnostic.parse_config(['--output', 'unused', *args])

    def test_kernel_cgroup_limits_not_just_docker_configuration(self):
        config = argparse.Namespace(cpu_limit=0.5, memory_mib=512)
        limits = {'cpu.max': '50000 100000', 'memory.max': '536870912', 'memory.swap.max': '0'}
        diagnostic.verify_cgroup_limits(config, limits)
        for key in limits:
            with self.subTest(key=key), self.assertRaises(diagnostic.ExecutionError):
                diagnostic.verify_cgroup_limits(config, dict(limits, **{key: 'max'}))

    def test_resource_limits_require_exact_readback(self):
        config = argparse.Namespace(cpu_limit=0.5, memory_mib=512)
        self.assertEqual(diagnostic.resource_options(config), ['--cpus', '0.5', '--memory', '536870912', '--memory-swap', '536870912'])
        host = {'NanoCpus': 500000000, 'Memory': 536870912, 'MemorySwap': 536870912}
        diagnostic.verify_resource_limits(config, host)
        for key in host:
            with self.subTest(key=key), self.assertRaises(diagnostic.ExecutionError):
                diagnostic.verify_resource_limits(config, dict(host, **{key: 0}))


class ScaleHelperTests(unittest.TestCase):
    def load(self, name):
        spec = diagnostic.importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / 'docker/path-lab' / (name + '.py'))
        module = diagnostic.importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_twenty_private_states_and_strict_initializer_inventory(self):
        provision = self.load('delivery-provision')
        raw = ('PLAYGROUND_INIT status=pass nodes=20 root=private\n' + ''.join(
            f'PLAYGROUND_NODE index={i} carrier_id={i:064x} mission_id={i+20:064x}\n' for i in range(20))).encode()
        self.assertEqual(len(provision.parse_nodes(raw, 20)), 20)
        with self.assertRaises(ValueError):
            provision.parse_nodes(raw.replace(b'index=19 ', b'index=18 '), 20)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(len(provision.create_state_targets(Path(directory), 20)), 20)

    def test_all_to_all_agent_peers_and_default_gateway(self):
        agent = self.load('delivery-agent')
        network = self.load('delivery-network-init')
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'peer').write_text(''.join(f'{i:064x}@10.77.{i}.2:4433={i:064x}\n' for i in range(1, 20)))
            argv = agent.agent_argv('node-t', state)
            self.assertEqual(argv.count('--peer'), 19)
            self.assertIn('10.77.20.2:4433', argv)
        commands = network.commands('node-t', 20)
        self.assertIn(['ip', 'route', 'replace', 'default', 'via', '10.77.20.1'], commands)

    def test_owned_docker_accepts_only_bounded_scale_roles(self):
        calls = []
        def run(argv, timeout):
            calls.append(argv)
            cidfile = Path(argv[argv.index('--cidfile') + 1])
            cidfile.write_text('a' * 64)
            cidfile.chmod(0o600)
            return b''
        with tempfile.TemporaryDirectory() as directory:
            owner = diagnostic.OwnedDocker('docker', Path(directory), run)
            owner.create('node-t', ['--network', 'none'], ['sleep', '10'])
            with self.assertRaises(diagnostic.ExecutionError):
                owner.create('node-u', [], [])


class OracleTests(unittest.TestCase):
    def test_image_cannot_become_a_docker_option(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(diagnostic.ExecutionError):
                diagnostic.OwnedDocker('docker', Path(directory), lambda *_: b'', image='--privileged')

    def test_completed_delivery_after_deadline_is_failure(self):
        event = {'id': 'a', 'logicalKey': 'aw==', 'payload': 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='}
        with patch.object(diagnostic.time, 'monotonic', return_value=11):
            with self.assertRaises(TimeoutError):
                diagnostic.verify_events({'a': event}, {'a': event}, deadline=10)

    def test_proc_disappearance_during_shutdown_is_success(self):
        with patch.object(Path, 'read_text', side_effect=ProcessLookupError(3, 'No such process')):
            diagnostic.wait_stopped(123)

    def test_publisher_admission_reserves_two_connections_and_preserves_work(self):
        import threading
        release = threading.Event()
        six_started = threading.Event()
        overflow = threading.Event()
        lock = threading.Lock()
        active = peak = 0

        class Client:
            def publish_event(self, key, payload):
                nonlocal active, peak
                with lock:
                    active += 1
                    peak = max(peak, active)
                    if active == 6:
                        six_started.set()
                    if active > 6:
                        overflow.set()
                release.wait(3)
                with lock:
                    active -= 1
                return {'id': key.decode(), 'payload': payload.decode()}

            def call(self, method, request):
                return {'deliveries': []}

        workload = diagnostic.Workload(Client(), 'sub', 'probe', 12, 1000, 32)
        try:
            self.assertTrue(six_started.wait(2))
            exceeded = overflow.wait(0.1)
            release.set()
            workload.publisher.join(3)
            result = workload.snapshot()
            self.assertFalse(exceeded, 'publishing consumed reserved consumer/status slots')
            self.assertEqual(peak, 6)
            self.assertEqual(len(result['accepted']), 12)
            self.assertEqual(result['errors'], [])
            self.assertGreater(result['max_schedule_lag_seconds'], 0.05)
        finally:
            release.set()
            workload.close()

    def test_publisher_checks_actual_start_not_executor_submission_time(self):
        import time
        original_executor = diagnostic.ThreadPoolExecutor
        calls = []

        class DelayedExecutor(original_executor):
            def submit(self, function, *args, **kwargs):
                def delayed():
                    time.sleep(1.05)
                    return function(*args, **kwargs)
                return super().submit(delayed)

        class Client:
            def publish_event(self, key, payload):
                calls.append(key)
                return {'id': key.decode()}

            def call(self, method, request):
                return {'deliveries': []}

        with patch.object(diagnostic, 'ThreadPoolExecutor', DelayedExecutor):
            workload = diagnostic.Workload(Client(), 'sub', 'probe', 1, 10, 32)
            workload.publisher.join(3)
            result = workload.snapshot()
            workload.close()
        self.assertEqual(calls, [])
        self.assertGreater(result['max_schedule_lag_seconds'], 1)
        self.assertEqual(result['errors'], ['bounded publisher could not maintain requested pace'])

    def test_publisher_admission_timeout_does_not_smooth_requested_rate(self):
        import threading
        release = threading.Event()

        class Client:
            def publish_event(self, key, payload):
                release.wait(3)
                return {'id': key.decode()}

            def call(self, method, request):
                return {'deliveries': []}

        workload = diagnostic.Workload(Client(), 'sub', 'probe', 7, 1000, 32)
        try:
            self.assertFalse(workload.stop.wait(1.2))
            result = workload.snapshot()
            self.assertGreater(result['max_schedule_lag_seconds'], 1)
            self.assertEqual(result['errors'], ['bounded publisher could not maintain requested pace'])
        finally:
            release.set()
            workload.publisher.join(3)
            workload.close()
        self.assertEqual(len(workload.snapshot()['accepted']), 6)

    def test_paced_workload_counts_rejection_and_unknown_failure(self):
        class Client:
            def publish_event(self, key, payload):
                if key.endswith(b'000001'):
                    return {'key': key.decode(), 'rejected': 'explicit test rejection'}
                return {'id': key.decode(), 'logicalKey': diagnostic.base64.b64encode(key).decode(),
                        'payload': diagnostic.base64.b64encode(payload).decode()}

            def call(self, method, request):
                return {'deliveries': []}

        workload = diagnostic.Workload(Client(), 'sub', 'probe', 3, 20, 32)
        workload.publisher.join(5)
        result = workload.snapshot()
        workload.close()
        self.assertTrue(result['done'])
        self.assertEqual(len(result['accepted']), 2)
        self.assertEqual(len(result['rejected']), 1)
        self.assertEqual(result['errors'], [])

        class Failed(Client):
            def publish_event(self, *args):
                raise diagnostic.RpcError('unknown outcome')

        workload = diagnostic.Workload(Failed(), 'sub', 'probe', 1, 20, 32)
        workload.publisher.join(5)
        result = workload.snapshot()
        workload.close()
        self.assertEqual(result['errors'], ['unknown outcome'])
        self.assertEqual(result['accepted'], {})

    def test_explicit_image_does_not_change_default_smoke(self):
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            path = Path(argv[argv.index('--cidfile') + 1])
            path.write_text('a' * 64)
            path.chmod(0o600)
            return b''

        with tempfile.TemporaryDirectory() as directory:
            owner = diagnostic.OwnedDocker('docker', Path(directory), run,
                                            image='aster-path-delivery:diagnostic-local')
            owner.create('wan', ['--network', 'none'], ['sleep', '10'])
            self.assertIn('aster-path-delivery:diagnostic-local', calls[-1])
        with tempfile.TemporaryDirectory() as directory:
            owner = diagnostic.OwnedDocker('docker', Path(directory), run)
            owner.create('wan', ['--network', 'none'], ['sleep', '10'])
            self.assertIn('aster-path-delivery:local', calls[-1])

    def test_exact_nonempty_delivery_required(self):
        event = {'id': 'a', 'logicalKey': 'aw==', 'payload': 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='}
        for exact in (False, True):
            self.assertEqual(diagnostic.verify_events({'a': event}, {'a': event}, exact=exact), 1)
            for accepted, actual in [({}, {}), ({'a': event}, {}),
                                     ({'a': event}, {'a': dict(event, payload='eQ==')}),
                                     ({'a': event}, {'a': dict(event, logicalKey='eg==')})]:
                with self.subTest(exact=exact, accepted=accepted, actual=actual):
                    with self.assertRaises(ValueError):
                        diagnostic.verify_events(accepted, actual, exact=exact)

    def test_setup_failure_always_cleans_owned_resources(self):
        cleaned = []

        class Owned:
            def __init__(self, *_, **kwargs):
                pass

            def create(self, *_):
                raise ValueError('injected setup failure')

            def cleanup(self):
                cleaned.append(True)
                return []

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, 'OwnedDocker', Owned):
                result = diagnostic.run_profile(argparse.Namespace(output=Path(directory)), 'baseline', {})
            self.assertEqual(result['status'], 'fail')
            self.assertEqual(result['error'], 'injected setup failure')
            self.assertEqual(cleaned, [True])
            self.assertEqual(result['cleanup_errors'], [])
            self.assertFalse(Path(result['ownership_directory']).exists())

    def test_receipt_write_failure_cannot_skip_cleanup(self):
        cleaned = []

        class Owned:
            def __init__(self, *_, **kwargs):
                pass

            def cleanup(self):
                cleaned.append(True)
                return []

        with tempfile.TemporaryDirectory() as directory:
            owned_path = Path(directory) / 'owned'
            owned_path.mkdir()
            with patch.object(diagnostic, 'OwnedDocker', Owned), \
                    patch.object(diagnostic.tempfile, 'mkdtemp', return_value=str(owned_path)), \
                    patch.object(Path, 'write_text', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    diagnostic.run_profile(argparse.Namespace(output=Path(directory)), 'baseline', {})
            self.assertEqual(cleaned, [True])

    def test_worker_timeout_is_failure_and_reaped(self):
        worker = diagnostic.Worker([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            with self.assertRaises(TimeoutError):
                worker.call('status', timeout=0.05)
        finally:
            worker.close()
        self.assertIsNotNone(worker.process.poll())

    def test_worker_eof_is_failure_and_reaped(self):
        worker = diagnostic.Worker([sys.executable, '-c', 'pass'])
        try:
            with self.assertRaises((ValueError, BrokenPipeError)):
                worker.call('status', timeout=1)
        finally:
            worker.close()
        self.assertIsNotNone(worker.process.poll())

    def test_query_exceeds_old_nine_page_limit(self):
        class Client:
            def call(self, method, request):
                marker = int(request['afterAcceptanceMarker'])
                return {'events': [{'id': str(marker)}], 'scannedThrough': str(marker + 1),
                        'hasMore': marker < 12}
        self.assertEqual(len(diagnostic.query_all(Client(), 20)), 13)
        with self.assertRaises(ValueError):
            diagnostic.query_all(Client(), 4)

    def test_netem_profiles_are_separate_and_bounded(self):
        self.assertNotIn('reorder', diagnostic.netem_args('impaired', 40, 5, 1, 100, 10))
        self.assertIn('reorder', diagnostic.netem_args('reorder', 40, 5, 1, 100, 10))
        self.assertEqual(diagnostic.netem_args('outage', 40, 5, 1, 100, 10), ['loss', '100%'])
        with self.assertRaises(ValueError):
            diagnostic.netem_args('invalid', 40, 5, 1, 100, 10)


class FinalizationTests(unittest.TestCase):
    """Real workload threads, with only Docker/IPC and the RPC peer replaced."""

    def run_profile(self, *, fail_ack=False, extra_event=False, shutdown_timeout=False, provenance_drift=False, bandwidth_kbit=None):
        import json
        import os
        import threading

        events = {role: {'id': role,
                        'logicalKey': diagnostic.base64.b64encode((role + '-000000').encode()).decode(),
                        'payload': diagnostic.base64.b64encode(b'n').decode()}
                  for role in ('node-a', 'node-b')}
        ack_entered = threading.Event()
        release_ack = threading.Event()
        workers = []
        actions = []
        cleaned = []
        testcase = self

        class Client:
            def __init__(self, role):
                self.role = role
                self.polled = False

            def publish_event(self, key, payload):
                if key.endswith(b'000001'):
                    return {'key': key.decode(), 'rejected': 'explicit test rejection'}
                return events[self.role]

            def call(self, method, request):
                if method == 'PollEvents':
                    if self.polled:
                        return {'deliveries': []}
                    self.polled = True
                    return {'deliveries': [{'event': event} for event in events.values()]}
                if method == 'AcknowledgeEvent' and self.role == 'node-a' and request['eventId'] == 'node-b':
                    ack_entered.set()
                    if not release_ack.wait(5):
                        raise TimeoutError('test acknowledgement release deadline')
                    if fail_ack:
                        raise ValueError('injected final acknowledgement failure')
                return {}

        class Worker:
            def __init__(self, argv):
                self.role = argv[argv.index('-i') + 1]
                self.workload = None
                workers.append(self)

            def call(self, action, **kwargs):
                actions.append((self.role, action))
                if action == 'start-workload':
                    self.workload = diagnostic.Workload(Client(self.role), 'sub', self.role, 2, 20, 1)
                    self.workload.publisher.join(5)
                elif action == 'progress':
                    testcase.assertTrue(ack_entered.wait(5))
                    assert self.workload is not None
                    return self.workload.snapshot()
                elif action in ('end-workload', 'stop'):
                    if action == 'end-workload' and self.role == 'node-a' and shutdown_timeout:
                        # Keep the real consumer blocked, but skip the ten-second join wait.
                        assert self.workload is not None
                        with patch.object(self.workload.consumer, 'join'):
                            self.workload.close()
                    # The final ack completes only AFTER drain has observed its delivery.
                    release_ack.set()
                    if self.workload:
                        self.workload.close()
                        if action == 'end-workload':
                            return self.workload.snapshot()
                    return {'stopped_pid': 123}
                elif action == 'query':
                    actual = dict(events)
                    if extra_event:
                        actual['unexpected'] = dict(events['node-a'], id='unexpected')

                    class QueryClient:
                        def call(self, method, request):
                            return {'events': list(actual.values()), 'hasMore': False}

                    return diagnostic.query_all(QueryClient(), kwargs['maximum'])
                return {}

            def close(self):
                release_ack.set()
                if self.workload:
                    self.workload.close()

        class Owned:
            def __init__(self, *args, **kwargs):
                pass

            def create(self, role, *args):
                return role

            def cleanup(self):
                cleaned.append(True)
                return []

        loss = [False]
        def command(argv, timeout):
            if '{{.Image}}' in argv:
                return ('sha256:' + 'a' * 64).encode()
            if 'inspect' in argv:
                return b'123'
            if any("os.stat('/target')" in arg for arg in argv):
                inode = os.stat('/proc/self/ns/net').st_ino
                return json.dumps([inode + 1, inode + 2]).encode()
            if 'sha256sum' in argv:
                return b'test-hash'
            if 'tc' in argv:
                if 'replace' in argv:
                    loss[0] = '100%' in argv
                    if bandwidth_kbit is not None:
                        testcase.assertEqual(argv[argv.index('netem') + 1:],
                            (['loss', '100%'] if loss[0] else []) + ['rate', '3kbit'])
                if '-j' in argv and bandwidth_kbit is not None:
                    return json.dumps([{'kind': 'netem', 'root': True, 'options': {'rate': {'rate': 375}}}]).encode()
                return b'[]' if '-j' in argv else (b'loss 100%' if loss[0] else b'delay 0ms')
            return b''

        with tempfile.TemporaryDirectory() as directory:
            config = argparse.Namespace(output=Path(directory), duration_seconds=1,
                events_per_second=2, payload_bytes=1, delay_ms=40, jitter_ms=5,
                loss_percent=1, rate_mbit=100, reorder_percent=10, bandwidth_kbit=bandwidth_kbit,
                restore_deadline_seconds=5, sample_seconds=5)
            if provenance_drift:
                config.image = 'sha256:' + 'a' * 64
                def validate():
                    if sum(action == 'query' for _, action in actions) == 2:
                        raise diagnostic.ExecutionError('source/helper drift during diagnostic')
                config.validate_provenance = validate
            with patch.object(diagnostic, 'OwnedDocker', Owned), \
                    patch.object(diagnostic, 'Worker', Worker), \
                    patch.object(diagnostic, '_pinned_docker', return_value=command):
                result = diagnostic.run_profile(config, 'baseline', {})
            self.assertEqual(json.loads((Path(directory) / 'baseline.json').read_text()), result)
        self.assertEqual(cleaned, [True])
        self.assertEqual(result['cleanup_errors'], [])
        self.assertFalse(Path(result['ownership_directory']).exists())
        for worker in workers:
            self.assertFalse(worker.workload.publisher.is_alive())
            self.assertFalse(worker.workload.consumer.is_alive())
        return result, actions

    def test_bandwidth_reaches_all_egresses_and_peerless_cut(self):
        result, _ = self.run_profile(bandwidth_kbit=3)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual([r['arguments'] for r in result['qdiscs']],
                         [['rate', '3kbit'], ['loss', '100%', 'rate', '3kbit']])
        for row in result['qdiscs']:
            self.assertEqual([c['interface'] for c in row['changes']], ['wan1', 'wan2'])

    def test_drift_after_peerless_results_prevents_profile_pass(self):
        result, _ = self.run_profile(provenance_drift=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('source/helper drift', result['error'])
        self.assertEqual(len(result['peerless']), 2)

    def test_final_ack_failure_after_drain_prevents_peerless_success(self):
        result, actions = self.run_profile(fail_ack=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('injected final acknowledgement failure', result['error'])
        self.assertIn('drain', [row['phase'] for row in result['phases']])
        self.assertNotIn('peerless', [action for _, action in actions])

    def test_peerless_extra_id_with_rejected_publications_fails(self):
        result, actions = self.run_profile(extra_event=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('Event ID set mismatch', result['error'])
        self.assertIn('query', [action for _, action in actions])
        self.assertEqual([len(rows) for rows in result['rejected'].values()], [1, 1])

    def test_pending_ack_shutdown_timeout_prevents_peerless_success(self):
        result, actions = self.run_profile(shutdown_timeout=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('workload thread shutdown deadline', result['error'])
        self.assertNotIn('peerless', [action for _, action in actions])

    def test_successful_final_ack_and_exact_peerless_inventory_pass(self):
        result, actions = self.run_profile()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual([row['exact_events'] for row in result['peerless'].values()], [2, 2])


class ProvenanceTests(unittest.TestCase):
    def run_campaign(self, drift=None):
        import json
        image = 'sha256:' + 'a' * 64
        identity = diagnostic.source_identity(Path(diagnostic.__file__).resolve().parents[1])
        checks = [0]
        used = []
        def snapshot(_root):
            checks[0] += 1
            changed = dict(identity)
            if used and drift:
                if drift == 'helper':
                    changed['helper_files_sha256'] = dict(identity['helper_files_sha256'],
                                                         **{'aster_mesh_playground.py': 'changed'})
                else:
                    changed['source_head'] = 'changed'
            return changed
        def profile(config, name, row):
            used.append(config.image)
            self.assertEqual(config.image, image)  # Tag may now point elsewhere.
            for helper in diagnostic.HELPER_FILES:
                self.assertEqual((config.helper_directory / helper).read_bytes(),
                                 Path(diagnostic.__file__).with_name(helper).read_bytes())
            row.update(profile=name, status='verified')
        def docker(argv, timeout):
            self.assertEqual(argv[-1], 'aster-path-delivery:local')
            return image.encode()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(sys, 'argv', ['diagnostic', '--output', directory]), \
                    patch.object(diagnostic, 'source_identity', side_effect=snapshot), \
                    patch.object(diagnostic, 'run_profile', side_effect=profile), \
                    patch.object(diagnostic, '_pinned_docker', return_value=docker), \
                    patch.object(diagnostic.signal, 'signal'):
                code = diagnostic.main()
            report = json.loads((Path(directory) / 'receipt.json').read_text())
            for path in Path(directory).glob('*.json'):
                if drift:
                    self.assertNotEqual(json.loads(path.read_text()).get('status'), 'pass')
        return code, report, used

    def test_retag_cannot_change_the_image_used_by_later_profiles(self):
        code, report, used = self.run_campaign()
        self.assertEqual(code, 0)
        self.assertEqual(used, [report['image_id']] * 4)
        self.assertEqual(report['status'], 'pass')

    def test_source_drift_fails_before_normal_receipts(self):
        code, report, used = self.run_campaign('source')
        self.assertEqual(code, 1)
        self.assertIn('source/helper drift', report['error'])
        self.assertEqual(len(used), 1)

    def test_helper_drift_fails_before_normal_receipts(self):
        code, report, used = self.run_campaign('helper')
        self.assertEqual(code, 1)
        self.assertIn('source/helper drift', report['error'])
        self.assertEqual(len(used), 1)

    def test_staged_only_change_is_in_source_diff_identity(self):
        import hashlib
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL)
            git('init')
            (root / 'tracked').write_text('before\n')
            git('add', 'tracked')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
            # Relevant untracked helper files must also have explicit identities.
            (root / 'tools').mkdir()
            for name in diagnostic.HELPER_FILES:
                (root / 'tools' / name).write_text('helper\n')
            before = diagnostic.source_identity(root)
            (root / 'tracked').write_text('staged only\n')
            git('add', 'tracked')
            self.assertEqual(git('diff', '--binary'), b'')
            after = diagnostic.source_identity(root)
            self.assertNotEqual(before['source_diff_sha256'], after['source_diff_sha256'])
            self.assertEqual(after['source_diff_sha256'], hashlib.sha256(git('diff', 'HEAD', '--binary')).hexdigest())
            (root / 'tools' / 'aster_mesh_playground.py').write_text('changed untracked helper\n')
            self.assertNotEqual(after['helper_files_sha256'], diagnostic.source_identity(root)['helper_files_sha256'])


class WorkflowTests(unittest.TestCase):
    """Dependency-free checks for the deliberately fixed manual launch."""

    @classmethod
    def setUpClass(cls):
        import re
        cls.workflow = (Path(__file__).resolve().parents[1] /
                        '.github/workflows/diagnostic-runtime-volume.yml').read_text()
        cls.scripts = re.findall(r'        run: \|\n((?:          .*\n|\n)+)', cls.workflow)
        cls.scripts = ['\n'.join(line[10:] for line in block.splitlines())
                       for block in cls.scripts]

    def test_optional_bandwidth_is_forwarded_without_shell_interpolation(self):
        import os
        import subprocess
        import shlex
        # Execute the exact preflight parser invocation and controller shell.
        preflight = next(line.strip() for line in self.scripts[0].splitlines()
                         if line.strip().startswith('PYTHONPATH=tools'))
        python_code = shlex.split(preflight)[3]
        root = str(Path(__file__).resolve().parents[1])
        base = dict(os.environ, PYTHONPATH=root + '/tools', AGENTS='2', EVENTS='600',
                    PAYLOAD='1024', RATE='10', CPU='0', MEMORY='0', DEADLINE='120',
                    STORAGE_ITEMS='10000', STORAGE_MIB='64', PROFILE='all')
        for value in ('', '0', '3', '1000000', '-1', '3.5', '1000001', '$(id)'):
            env = dict(base, BANDWIDTH_KBIT=value)
            valid = value in ('', '0', '3', '1000000')
            result = subprocess.run([sys.executable, '-c', python_code], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, valid, value)
            if not valid:
                continue
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / 'artifacts/path-diagnostic').mkdir(parents=True)
                launched = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c',
                    'timeout() { printf "%s\\n" "$@"; };\n' + self.scripts[2]],
                    cwd=directory, env=env, capture_output=True, text=True)
                self.assertEqual(launched.returncode, 0, launched.stderr)
                argv = launched.stdout.splitlines()
                self.assertEqual('--bandwidth-kbit' in argv, value != '')
                if value:
                    self.assertEqual(argv[argv.index('--bandwidth-kbit') + 1], value)

    def test_manual_read_only_pinned_and_always_retained(self):
        import re
        text = self.workflow
        self.assertIn('on:\n  workflow_dispatch:\n    inputs:', text)
        self.assertIn('permissions:\n  contents: read\n', text)
        self.assertIn('name: "Diagnostic: load, scale and network faults"', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('timeout-minutes: 90', text)
        self.assertIn('if: ${{ always() }}', text)
        self.assertIn('path: artifacts/path-diagnostic/', text)
        self.assertIn('retention-days: 14', text)
        self.assertEqual(len(re.findall(r'uses: [\w/-]+@[0-9a-f]{40} ', text)), 4)
        for forbidden in ('pull_request:', 'push:', 'sudo ', '--privileged',
                          '--network=host', 'docker system prune', 'continue-on-error:'):
            self.assertNotIn(forbidden, text)

    def test_shell_syntax_and_canonical_build(self):
        import subprocess
        self.assertEqual(len(self.scripts), 4)
        for script in self.scripts:
            subprocess.run(['bash', '-n'], input=script, text=True, check=True)
            self.assertNotIn('${{', script)
        self.assertIn('--file docker/path-lab/Dockerfile.delivery', self.scripts[1])
        self.assertIn('--tag aster-path-delivery:local .', self.scripts[1])
        self.assertIn('timeout --signal=TERM --kill-after=300s 50m', self.scripts[2])
        self.assertIn('2>&1 | tee artifacts/path-diagnostic/controller.log', self.scripts[2])

    def test_buildkit_cache_is_persistent_scoped_and_loaded(self):
        text = self.workflow
        self.assertIn('uses: docker/setup-buildx-action@', text)
        self.assertIn('driver: docker-container', text)
        self.assertIn('uses: crazy-max/ghaction-github-runtime@', text)
        self.assertLess(text.index('uses: crazy-max/ghaction-github-runtime@'),
                        text.index('id: build\n'))
        script = self.scripts[1]
        self.assertIn('docker buildx build --load --pull=false --progress=plain', script)
        self.assertIn('--cache-from type=gha,version=2,scope=aster-path-diagnostic-delivery-amd64-v1', script)
        self.assertIn('--cache-to type=gha,version=2,scope=aster-path-diagnostic-delivery-amd64-v1,mode=max', script)
        self.assertIn('timeout --signal=TERM --kill-after=30s 30m', script)
        self.assertNotIn('ignore-error=true', script)

    def test_build_exit_and_logs_survive_success_failure_and_timeout(self):
        import subprocess
        for code in (0, 1, 124, 137):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'artifacts/path-diagnostic'
                root.mkdir(parents=True)
                result = subprocess.run(
                    ['bash', '-e', '-o', 'pipefail', '-c',
                     f'timeout() {{ printf "build-output\\n"; return {code}; }};\n' + self.scripts[1]],
                    cwd=directory, capture_output=True, text=True)
                self.assertEqual(result.returncode, code)
                self.assertEqual((root / 'build-exit-code').read_text().strip(), str(code))
                self.assertEqual((root / 'build.log').read_text(), 'build-output\n')

    def test_preflight_failure_survives_log_pipeline(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            # A failing first command must not be hidden by later checks or tee.
            result = subprocess.run(
                ['bash', '-e', '-o', 'pipefail', '-c',
                 'git() { return 23; };\n' + self.scripts[0]],
                cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)
            self.assertTrue((Path(directory) / 'artifacts/path-diagnostic/preflight.log').is_file())

    def test_controller_exit_survives_tee_and_records_timeout(self):
        import os
        import subprocess
        for code in (1, 124, 137):
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / 'artifacts/path-diagnostic').mkdir(parents=True)
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c',
                    f'timeout() {{ return {code}; }};\n' + self.scripts[2]], cwd=directory,
                    env=dict(os.environ, PROFILE='baseline'), capture_output=True, text=True)
                self.assertEqual(result.returncode, code)
                self.assertEqual((Path(directory) / 'artifacts/path-diagnostic/run-exit-code').read_text().strip(), str(code))

    def test_launch_arguments_use_actual_cli_defaults(self):
        import shlex
        script = self.scripts[2].replace('\\\n', '')
        argv = shlex.split(script)
        start = argv.index('tools/aster_path_diagnostic.py')
        argv = argv[start:argv.index('2>&1')]
        for name in ('agents', 'events-per-agent', 'payload-bytes', 'events-per-second',
                     'cpu-limit', 'memory-mib', 'restore-deadline-seconds'):
            self.assertIn('--' + name, argv)
        for name in ('AGENTS', 'EVENTS', 'PAYLOAD', 'RATE', 'CPU', 'MEMORY', 'DEADLINE', 'PROFILE'):
            self.assertIn('"$' + name + '"', self.scripts[2])
        argv = ['diagnostic', '--output', 'artifacts/path-diagnostic']
        configurations = []

        def profile(config, name, row):
            configurations.append((name, config))
            row.update(profile=name, status='verified')

        with tempfile.TemporaryDirectory() as directory:
            argv[-1] = directory
            with patch.object(sys, 'argv', argv), \
                    patch.object(diagnostic, 'run_profile', side_effect=profile), \
                    patch.object(diagnostic, '_run_command', return_value=b'test-source'), \
                    patch.object(diagnostic, '_pinned_docker', return_value=lambda *_: ('sha256:' + 'a' * 64).encode()), \
                    patch.object(diagnostic.signal, 'signal'):
                self.assertEqual(diagnostic.main(), 0)
        self.assertEqual([name for name, _ in configurations],
                         ['baseline', 'impaired', 'reorder', 'outage'])
        config = configurations[0][1]
        self.assertEqual((config.duration_seconds, config.events_per_second, config.payload_bytes),
                         (60, 10, 1024))
        self.assertEqual((config.reorder_percent, config.outage_seconds, config.restore_deadline_seconds),
                         (10, 10, 120))
        self.assertEqual((config.image, config.build_kind),
                         ('sha256:' + 'a' * 64, 'canonical-release'))


if __name__ == '__main__':
    unittest.main()
