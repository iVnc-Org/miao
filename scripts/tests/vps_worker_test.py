"""Run: python3 -m unittest discover -s scripts/tests -p '*_test.py' -v
All deployment paths and external commands are isolated/mocked. No real VPS.
The optional core test binds loopback only and never uses external services.
"""
import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'src/services/vps/worker.py'
spec = importlib.util.spec_from_file_location('vps_worker', SOURCE)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = []
        for name, relative in [('ROOT', 'state'), ('CONFIG', 'etc/hysteria'), ('BINARY', 'usr/local/bin/hysteria'), ('UNIT', 'etc/systemd/system/hysteria-server.service'), ('RC', 'etc/init.d/hysteria-server'), ('LOGROTATE', 'etc/logrotate.d/miao-hysteria')]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.start(patch.object(w, name, path))
        w.ROOT.mkdir(mode=0o700)
        (w.ROOT / 'tasks').mkdir(mode=0o700)
        self.task = w.ROOT / 'tasks' / ('a' * 48)
        self.task.mkdir(mode=0o700)
        self.req = {'id': self.task.name, 'listen_port': 543, 'node_host': '127.0.0.1', 'node_port': 30543, 'name': '中文节点', 'download_proxy': ''}
        self.state = {'running': False, 'enabled': False}
        self.kind = 'systemd'
        self.start(patch.object(w, 'init_kind', side_effect=lambda: self.kind))
        self.start(patch.object(w.os, 'geteuid', return_value=0))
        self.start(patch.object(w.platform, 'system', return_value='Linux'))
        self.start(patch.object(w.platform, 'machine', return_value='x86_64'))
        self.start(patch.object(w.shutil, 'disk_usage', return_value=type('Disk', (), {'free': 1024**3})()))
        self.start(patch.object(w.shutil, 'chown'))
        self.start(patch.object(w, 'run', side_effect=self.fake_run))
        self.start(patch.object(w, 'download', side_effect=self.download))
        self.start(patch.object(w, 'verify_listener'))
        self.start(patch.object(w, 'enabled', side_effect=lambda _kind: self.state['enabled']))
        self.start(patch.object(w, 'stable', side_effect=lambda _kind: None if self.state['running'] else (_ for _ in ()).throw(RuntimeError('unhealthy'))))
        self.start(patch.object(w, 'result_node', side_effect=lambda req, config, ident: {'password': config['auth']['password'], 'obfs': config['obfs'], 'server_port': req['node_port'], 'tls': {'insecure': False}}))
        self.fail = ''
        self.restarts = 0

    def start(self, item):
        self.patches.append(item)
        return item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def fake_run(self, args, timeout=60, check=True):
        out = ''
        code = 0
        if args[0] == 'systemctl':
            action = args[1]
            if action == 'is-active': code = 0 if self.state['running'] else 3
            elif action == 'is-enabled': code = 0 if self.state['enabled'] else 1
            elif action == 'stop': self.state['running'] = False
            elif action == 'enable': self.state['enabled'] = True
            elif action == 'disable': self.state['enabled'] = False
            elif action == 'restart':
                self.restarts += 1
                if self.fail == 'restart' and self.restarts == 1:
                    raise RuntimeError('restart_failed')
                if self.fail == 'restore': raise RuntimeError('restart_failed')
                self.state['running'] = True
        elif args[0] == 'rc-service':
            action = args[2]
            if action == 'status': code = 0 if self.state['running'] else 3
            elif action == 'stop': self.state['running'] = False
            elif action == 'restart':
                self.restarts += 1
                if self.fail == 'restart' and self.restarts == 1: raise RuntimeError('restart_failed')
                self.state['running'] = True
        elif args[0] == 'rc-update':
            self.state['enabled'] = args[1] == 'add'
            runlevel = self.root / 'runlevel'
            runlevel.mkdir(exist_ok=True)
            entry = runlevel / 'hysteria-server'
            if args[1] == 'add': entry.touch()
            elif entry.exists(): entry.unlink()
        elif args[0] == 'ss':
            out = 'UNCONN 0 0 0.0.0.0:543 0.0.0.0:*' if self.fail == 'port' else ''
        elif args[0] == 'openssl':
            if args[1] == 'req':
                if self.fail == 'certificate': raise RuntimeError('certificate_failed')
                Path(args[args.index('-keyout') + 1]).write_text('test-key')
                Path(args[args.index('-out') + 1]).write_text('test-cert')
            elif '-ext' in args: out = '' if self.fail == 'legacy' else 'DNS:miao-hysteria'
            else: out = 'subject=CN = miao-hysteria'
        elif args[-1] == 'version': out = 'Version: v2.12.1'
        if check and code: raise subprocess.CalledProcessError(code, args)
        return subprocess.CompletedProcess(args, code, stdout=out, stderr='')

    def download(self, url, path, prefix, progress=None):
        if url.endswith('hashes.txt'):
            digest = 'bad' if self.fail == 'checksum' else hashlib.sha256(b'new-binary').hexdigest()
            path.write_text(digest + '  build/hysteria-linux-amd64\n')
        else: path.write_bytes(b'new-binary')

    def existing(self, managed=True):
        w.CONFIG.mkdir(mode=0o700)
        config = {'listen': ':543', 'tls': {'cert': str(w.CONFIG / 'server.crt'), 'key': str(w.CONFIG / 'server.key')},
                  'auth': {'type': 'password', 'password': "a'# : \n 中文"},
                  'obfs': {'type': 'salamander', 'salamander': {'password': 'old-obfs'}},
                  'masquerade': {'type': 'proxy', 'proxy': {'url': 'https://www.bing.com/'}}, 'ignoreClientBandwidth': True}
        w.atomic(w.CONFIG / 'config.yaml', config)
        (w.CONFIG / 'server.crt').write_text('old-cert')
        (w.CONFIG / 'server.key').write_text('old-key')
        w.BINARY.write_text('old-binary')
        w.UNIT.write_text('ExecStart=' + str(w.BINARY) + ' server -c ' + str(w.CONFIG / 'config.yaml'))
        if managed:
            w.atomic(w.ROOT / 'deployment.json', {'id': 'test-id', 'config_sha256': hashlib.sha256((w.CONFIG / 'config.yaml').read_bytes()).hexdigest()})
        self.state.update(running=True, enabled=True)
        return config

    def status(self):
        return json.loads((self.task / 'status.json').read_text())

    def test_progress_preserves_fast_phases_and_download_without_secret_history(self):
        w.publish_status(self.task, 'checking')
        w.publish_status(self.task, 'downloading', downloaded=4096, total=4096, source='direct')
        w.publish_status(self.task, 'verifying_download')
        w.publish_status(self.task, 'remote_ready', node={'password': 'never-copy-to-history'})
        value = json.loads((self.task / 'status.json').read_text())
        self.assertEqual(value['phase_history'], ['checking', 'downloading', 'verifying_download', 'remote_ready'])
        self.assertEqual(value['downloaded'], 4096)
        self.assertNotIn('never-copy-to-history', json.dumps(value['phase_history']))
        w.publish_status(self.task, 'checking')
        self.assertNotIn('node', json.loads((self.task / 'status.json').read_text()))

    def test_progress_is_bounded_with_stable_offsets_and_no_duplicate_phase(self):
        for i in range(110):
            w.publish_status(self.task, 'checking' if i % 2 == 0 else 'downloading')
        value = json.loads((self.task / 'status.json').read_text())
        self.assertEqual(len(value['phase_history']), 100)
        self.assertEqual(value['phase_history_start'], 10)
        w.publish_status(self.task, 'downloading', downloaded=2048)
        repeated = json.loads((self.task / 'status.json').read_text())
        self.assertEqual(repeated['phase_history_start'], 10)
        self.assertEqual(repeated['phase_history'], value['phase_history'])

    def test_new_install_uses_nat_port_and_secure_node(self):
        w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'remote_ready')
        self.assertEqual(self.status()['node']['server_port'], 30543)
        self.assertFalse(self.status()['node']['tls']['insecure'])
        self.assertTrue(self.state['running'])
        self.assertTrue((self.task / 'backup').is_dir())
        self.assertEqual((w.CONFIG / 'config.yaml').stat().st_mode & 0o777, 0o600)

    def test_recovery_does_not_restart_or_modify_existing(self):
        config = self.existing()
        before = (w.CONFIG / 'config.yaml').read_bytes()
        w.execute(self.req, self.task)
        self.assertEqual(self.restarts, 0)
        self.assertIn('recovering_existing', self.status()['phase_history'])
        self.assertEqual((w.CONFIG / 'config.yaml').read_bytes(), before)
        self.assertEqual(self.status()['node']['password'], config['auth']['password'])

    def test_openrc_arm64_install_and_rollback(self):
        self.kind = 'openrc'
        self.start(patch.object(w.platform, 'machine', return_value='aarch64'))
        def arm_download(url, path, prefix, progress=None):
            if url.endswith('hashes.txt'):
                path.write_text(hashlib.sha256(b'new-binary').hexdigest() + '  build/hysteria-linux-arm64\n')
            else: path.write_bytes(b'new-binary')
        self.start(patch.object(w, 'download', side_effect=arm_download))
        w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'remote_ready')
        self.assertTrue(w.RC.exists())
        self.assertIn('command_user="miao-hysteria:miao-hysteria"', w.RC.read_text())
        self.assertTrue(self.state['enabled'])

    def test_openrc_activation_failure_restores_absence(self):
        self.kind = 'openrc'
        self.fail = 'restart'
        with self.assertRaises(RuntimeError): w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'rolled_back')
        self.assertFalse(w.RC.exists())
        self.assertFalse(self.state['enabled'])

    def test_unknown_deployment_is_protected(self):
        w.CONFIG.mkdir()
        (w.CONFIG / 'config.yaml').write_text('auth: {}')
        with self.assertRaisesRegex(RuntimeError, 'third_party'):
            w.execute(self.req, self.task)
        self.assertEqual((w.CONFIG / 'config.yaml').read_text(), 'auth: {}')

    def test_modified_managed_config_is_protected(self):
        self.existing()
        (w.CONFIG / 'config.yaml').write_text('{}')
        with self.assertRaises(RuntimeError): w.execute(self.req, self.task)
        self.assertEqual((w.CONFIG / 'config.yaml').read_text(), '{}')

    def test_legacy_migration_preserves_password_obfs_and_custom_options(self):
        config = self.existing(False)
        self.fail = 'legacy'
        w.execute(self.req, self.task)
        after = json.loads((w.CONFIG / 'config.yaml').read_text())
        self.assertEqual(after['auth'], config['auth'])
        self.assertEqual(after['obfs'], config['obfs'])
        self.assertTrue(after['ignoreClientBandwidth'])
        self.assertEqual(self.status()['stage'], 'remote_ready')

    def test_activation_failure_restores_legacy_files_and_state(self):
        self.existing(False)
        old_inspect = w.inspect
        def inspect(req):
            info, config = old_inspect(req)
            info['action'] = 'migrate'
            return info, config
        self.start(patch.object(w, 'inspect', side_effect=inspect))
        before = (w.CONFIG / 'config.yaml').read_bytes()
        self.fail = 'restart'
        with self.assertRaises(RuntimeError): w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'rolled_back')
        self.assertEqual((w.CONFIG / 'config.yaml').read_bytes(), before)
        self.assertEqual(w.BINARY.read_text(), 'old-binary')
        self.assertTrue(self.state['running'])
        self.assertTrue(self.state['enabled'])

    def test_failed_first_install_restores_absence(self):
        self.fail = 'restart'
        with self.assertRaises(RuntimeError): w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'rolled_back')
        self.assertFalse(w.CONFIG.exists())
        self.assertFalse(w.BINARY.exists())
        self.assertFalse(w.UNIT.exists())
        self.assertFalse(self.state['enabled'])

    def test_checksum_failure_never_installs(self):
        self.fail = 'checksum'
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            w.execute(self.req, self.task)
        self.assertFalse(w.CONFIG.exists())
        self.assertFalse((self.task / 'journal.json').exists())

    def test_cleanup_failure_never_rolls_back_a_published_node(self):
        original_remove = w.remove
        def fail_cleanup(path):
            if path == self.task / 'binary': raise RuntimeError('cleanup_interrupted')
            original_remove(path)
        self.start(patch.object(w, 'remove', side_effect=fail_cleanup))
        with self.assertRaisesRegex(RuntimeError, 'cleanup_interrupted'): w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'remote_ready')
        self.assertEqual(json.loads((self.task / 'journal.json').read_text())['phase'], 'healthy')
        self.assertTrue(w.CONFIG.exists())
        self.assertTrue(self.state['running'])

    def test_port_conflict_never_installs(self):
        self.fail = 'port'
        with self.assertRaisesRegex(RuntimeError, 'port'):
            w.execute(self.req, self.task)
        self.assertFalse(w.CONFIG.exists())

    def test_symlink_is_rejected(self):
        w.CONFIG.symlink_to(self.root / 'other')
        with self.assertRaisesRegex(RuntimeError, 'symlink'): w.inspect(self.req)

    def test_reconcile_does_not_install_after_interrupted_preparation(self):
        w.execute(self.req, self.task, reconcile=True)
        self.assertEqual(self.status()['error'], 'interrupted_before_activation')
        self.assertFalse(w.CONFIG.exists())

    def test_interrupted_activation_is_rolled_back_before_other_work(self):
        backup = self.task / 'backup'
        backup.mkdir()
        w.CONFIG.mkdir()
        (w.CONFIG / 'half-written').write_text('partial')
        w.atomic(self.task / 'journal.json', {'phase': 'activating', 'init': 'systemd', 'running': False, 'enabled': False})
        w.execute(self.req, self.task, reconcile=True)
        self.assertEqual(self.status()['stage'], 'rolled_back')
        self.assertFalse(w.CONFIG.exists())

    def test_host_lock_prevents_competing_deployment(self):
        import fcntl
        with open(w.ROOT / 'deploy.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(w, 'LOCK_WAIT_SECONDS', 0):
                with self.assertRaisesRegex(RuntimeError, 'host_deployment_busy_timeout'):
                    w.execute(self.req, self.task)
            self.assertEqual(self.status()['stage'], 'waiting_for_deployment')
            self.assertFalse(w.CONFIG.exists())
            self.assertEqual(w.preflight(self.req), {'action': 'busy'})

    def test_waiting_client_rechecks_and_recovers_completed_deployment(self):
        import fcntl
        with w.deployment_lock() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def finish_first_deployment(_seconds):
                self.existing()
                fcntl.flock(lock, fcntl.LOCK_UN)
            with patch.object(w.time, 'sleep', side_effect=finish_first_deployment):
                w.execute(self.req, self.task)
        self.assertEqual(self.status()['stage'], 'remote_ready')
        self.assertIn('waiting_for_deployment', self.status()['phase_history'])
        self.assertIn('recovering_existing', self.status()['phase_history'])
        self.assertEqual(self.restarts, 0)
        w.download.assert_not_called()

    def test_preflight_preserves_real_blockers_after_lock_release(self):
        config = self.existing()
        config['auth']['password'] = 'externally-modified'
        w.atomic(w.CONFIG / 'config.yaml', config)
        with self.assertRaisesRegex(RuntimeError, 'managed_config_changed'):
            w.preflight(self.req)

    def test_lock_symlink_is_rejected(self):
        target = self.root / 'unrelated'
        target.write_text('unchanged')
        (w.ROOT / 'deploy.lock').symlink_to(target)
        with self.assertRaises(OSError):
            w.preflight(self.req)
        self.assertEqual(target.read_text(), 'unchanged')


class BootstrapTests(unittest.TestCase):
    def test_installs_only_missing_yaml_and_never_runs_real_package_manager(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tools = root / 'bin'; tools.mkdir()
            state = root / 'state'; state.mkdir()
            init = root / 'systemd'; init.mkdir()
            ca = root / 'ca.pem'; ca.write_text('fixture')
            flag = root / 'yaml-installed'
            calls = root / 'calls'
            def command(name, body):
                path = tools / name
                path.write_text('#!/bin/sh\n' + body + '\n'); path.chmod(0o700)
            command('id', 'echo 0')
            command('uname', 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac')
            command('systemctl', 'exit 0')
            for tool in ['openssl', 'ss', 'setcap']: command(tool, 'exit 0')
            command('python3', 'case "$*" in *yaml*) [ -f ' + str(flag) + ' ];; *) exit 0;; esac')
            command('apt-get', 'echo "$*" >> ' + str(calls) + '; touch ' + str(flag))
            source = SOURCE.with_name('bootstrap.sh').read_text().replace('/var/lib/miao-vps', str(state)).replace('/run/systemd/system', str(init)).replace('/etc/ssl/certs/ca-certificates.crt', str(ca))
            result = subprocess.run(['/bin/sh', '-s'], input=source, text=True, capture_output=True, env={'PATH': str(tools) + ':/usr/bin:/bin'}, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('install -y python3-yaml', calls.read_text())
            self.assertNotIn('openssl', calls.read_text())
            self.assertNotIn('upgrade', calls.read_text())


class CoreLoopbackTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('MIAO_TEST_SING_BOX'), 'set MIAO_TEST_SING_BOX for real core interoperability test')
    def test_gecko_strict_tls_and_wrong_certificate_rejected(self):
        binary = str(Path(os.environ['MIAO_TEST_SING_BOX']).resolve())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for prefix in ['server', 'wrong']:
                subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1', '-keyout', str(root / (prefix + '.key')), '-out', str(root / (prefix + '.crt')), '-subj', '/CN=miao-hysteria', '-addext', 'subjectAltName=DNS:miao-hysteria'], check=True, capture_output=True)
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self): self.send_response(204); self.end_headers()
                def log_message(self, *_args): pass
            httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0)); port = udp.getsockname()[1]; udp.close()
            server = {'log': {'disabled': True}, 'inbounds': [{'type': 'hysteria2', 'tag': 'server', 'listen': '127.0.0.1', 'listen_port': port, 'users': [{'password': 'secret'}], 'obfs': {'type': 'gecko', 'password': 'obfs-secret'}, 'tls': {'enabled': True, 'certificate_path': str(root / 'server.crt'), 'key_path': str(root / 'server.key')}}], 'outbounds': [{'type': 'direct'}]}
            path = root / 'server.json'; path.write_text(json.dumps(server))
            children = []
            try:
                children.append(subprocess.Popen([binary, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                for prefix in ['server', 'wrong']:
                    tcp = socket.socket(); tcp.bind(('127.0.0.1', 0)); socks_port = tcp.getsockname()[1]; tcp.close()
                    client = {'log': {'disabled': True}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks_port}], 'outbounds': [{'type': 'hysteria2', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': port, 'password': 'secret', 'obfs': {'type': 'gecko', 'password': 'obfs-secret'}, 'tls': {'enabled': True, 'server_name': 'miao-hysteria', 'insecure': False, 'certificate': [(root / (prefix + '.crt')).read_text()]}}]}
                    path = root / (prefix + '-client.json'); path.write_text(json.dumps(client))
                    subprocess.run([binary, 'check', '-c', str(path)], check=True, capture_output=True)
                    children.append(subprocess.Popen([binary, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                    time.sleep(.5)
                    with socket.create_connection(('127.0.0.1', socks_port), timeout=8) as sock:
                        sock.sendall(b'\x05\x01\x00'); self.assertEqual(sock.recv(2), b'\x05\x00')
                        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', httpd.server_port))
                        response = sock.recv(10)
                        if prefix == 'wrong':
                            self.assertTrue(not response or response[1] != 0)
                        else:
                            self.assertEqual(response[1], 0)
                            sock.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                            self.assertIn(b'204', sock.recv(1024))
            finally:
                for child in children:
                    child.terminate()
                for child in children:
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait()
                httpd.shutdown(); httpd.server_close(); thread.join()


if __name__ == '__main__': unittest.main()
