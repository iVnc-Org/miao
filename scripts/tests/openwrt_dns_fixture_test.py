"""Registry and cleanup regressions without root, daemons or namespaces."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import call, patch

import openwrt_dns_fixture as fixture


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.database = self.directory / 'services.json'
        self.dns = fixture.DNSFixture.__new__(fixture.DNSFixture)
        self.dns.directory = self.directory
        self.dns.trace_process = None
        termination = patch.object(fixture, 'terminate')
        termination.start()
        self.addCleanup(termination.stop)

    def dispatch(self, *args):
        with patch.dict(os.environ, MIAO_DNS_FIXTURE_DIR=str(self.directory), MIAO_DNSMASQ_BINARY='unused-dnsmasq'), \
                patch.object(fixture.sys, 'argv', ['fixture', *args]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            fixture.dispatch()
        return json.loads(output.getvalue())

    def test_close_waits_for_writer_and_terminates_published_processes(self):
        self.database.write_text(json.dumps({'old': {'instances': {'guard': {'pid': 10}}}}))
        published = {
            'dnsmasq': {'instances': {'fixture': {'pid': 11}}},
            'guard': {'instances': {'guard': {'pid': 12}}},
        }
        truncated, reader_attempt = threading.Event(), threading.Event()
        real_flock, real_read = fixture.fcntl.flock, Path.read_text
        failures = []

        def writer():
            try:
                with (self.directory / 'services.lock').open('w') as lock:
                    real_flock(lock, fixture.fcntl.LOCK_EX)
                    with self.database.open('w') as stream:
                        truncated.set()
                        if not reader_attempt.wait(5):
                            raise TimeoutError('cleanup did not access the registry')
                        stream.write(json.dumps(published))
            except BaseException as error:
                failures.append(error)

        def observed_flock(*args):
            reader_attempt.set()
            return real_flock(*args)

        def observed_read(path, *args, **kwargs):
            content = real_read(path, *args, **kwargs)
            if path == self.database:
                reader_attempt.set()
            return content

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        try:
            self.assertTrue(truncated.wait(5))
            with patch.object(fixture.fcntl, 'flock', side_effect=observed_flock), \
                    patch.object(Path, 'read_text', observed_read), \
                    patch.object(fixture, 'alive', return_value=True), \
                    patch.object(fixture, 'terminate') as terminate:
                self.dns.close()
                terminate.assert_has_calls([call(11), call(12)], any_order=True)
                self.assertEqual(terminate.call_count, 2)
        finally:
            reader_attempt.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    def test_failed_registry_write_preserves_previous_snapshot(self):
        previous = {'guard': {'instances': {'guard': {'pid': 10}}}}
        self.database.write_text(json.dumps(previous))

        def interrupted_write(path, _content, *args, **kwargs):
            with path.open('w') as stream:
                stream.write('{')
            raise OSError('simulated interrupted registry write')

        with patch.object(Path, 'write_text', interrupted_write), \
                self.assertRaisesRegex(OSError, 'interrupted registry write'):
            self.dispatch('call', 'service', 'delete', json.dumps({'name': 'guard'}))
        self.assertEqual(json.loads(self.database.read_text()), previous)
        self.assertEqual(list(self.directory.glob('*.tmp')), [])

    def test_close_prevents_queued_daemons_but_allows_deletion(self):
        self.database.write_text(json.dumps({'guard': {'instances': {'guard': {'pid': 10}}}}))
        with patch.object(fixture, 'alive', return_value=False):
            self.dns.close()
            self.dns.close()
            request = {'name': 'late', 'instances': {'guard': {
                'command': ['unused'], 'respawn': ['3600', '1', '5'],
            }}}
            with patch.object(fixture.subprocess, 'Popen') as spawn:
                for args in [('restart', 'fixture'), ('call', 'service', 'set', json.dumps(request))]:
                    with self.subTest(command=args[0]):
                        with self.assertRaises(SystemExit) as stopped:
                            self.dispatch(*args)
                        self.assertEqual(stopped.exception.code, 1)
                spawn.assert_not_called()
            self.assertEqual(self.dispatch('call', 'service', 'delete', json.dumps({'name': 'guard'})), {})
            self.assertEqual(json.loads(self.database.read_text()), {})

    def test_close_without_registry_is_idempotent(self):
        with patch.object(fixture, 'terminate') as terminate:
            self.dns.close()
            self.dns.close()
            terminate.assert_not_called()

    def test_invalid_published_registry_is_reported(self):
        self.database.write_text('')
        with self.assertRaises(json.JSONDecodeError):
            self.dns.close()


if __name__ == '__main__':
    unittest.main()
