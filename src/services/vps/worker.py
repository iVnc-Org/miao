"""Miao remote worker. Root-owned task/result files; no SSH credentials.
Invoked by a detached launcher. All mutations hold a host-wide flock.
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = Path('/var/lib/miao-vps')
CONFIG = Path('/etc/hysteria')
BINARY = Path('/usr/local/bin/hysteria')
UNIT = Path('/etc/systemd/system/hysteria-server.service')
RC = Path('/etc/init.d/hysteria-server')
LOGROTATE = Path('/etc/logrotate.d/miao-hysteria')
VERSION = 'v2.12.1'
SERVICE = 'hysteria-server'


def run(args, timeout=60, check=True):
    # Never return raw subprocess output to the UI: it can include config secrets.
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check, text=True)


def atomic(path, value, mode=0o600):
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def init_kind():
    if shutil.which('systemctl') and Path('/run/systemd/system').is_dir():
        return 'systemd'
    if shutil.which('rc-service') and shutil.which('rc-update') and Path('/run/openrc').exists():
        return 'openrc'
    raise RuntimeError('unsupported_init')


def service(action, kind, check=True):
    args = ['systemctl', action, SERVICE] if kind == 'systemd' else ['rc-service', SERVICE, action]
    return run(args, check=check)


def running(kind):
    return service('is-active' if kind == 'systemd' else 'status', kind, False).returncode == 0


def enabled(kind):
    if kind == 'systemd':
        return service('is-enabled', kind, False).returncode == 0
    return (Path('/etc/runlevels/default') / SERVICE).exists()


def autostart(value, kind):
    if kind == 'systemd':
        service('enable' if value else 'disable', kind)
    else:
        run(['rc-update', 'add' if value else 'del', SERVICE, 'default'])


def reload(kind):
    if kind == 'systemd':
        run(['systemctl', 'daemon-reload'])


def stable(kind):
    for _ in range(5):
        time.sleep(1)
        if not running(kind):
            raise RuntimeError('service_unhealthy')
    # Listener ownership and end-to-end proxy verification are checked separately.


def verify_listener(kind, port):
    if kind == 'systemd':
        pid = run(['systemctl', 'show', SERVICE, '--property=MainPID', '--value']).stdout.strip()
    else:
        pid = Path('/run/hysteria-server.pid').read_text().strip()
    if not pid.isdigit() or pid == '0':
        raise RuntimeError('service_pid_missing')
    sockets = run(['ss', '-H', '-lunp']).stdout
    if not any(len(parts := line.split()) > 3 and parts[3].rsplit(':', 1)[-1] == str(port)
               and ('pid=' + pid + ',') in line for line in sockets.splitlines()):
        raise RuntimeError('service_udp_listener_missing')


def inspect(req):
    if os.geteuid() != 0 or platform.system() != 'Linux':
        raise RuntimeError('requires_root_linux')
    if platform.machine() not in ('x86_64', 'aarch64', 'arm64'):
        raise RuntimeError('unsupported_architecture')
    kind = init_kind()
    for path in (ROOT, ROOT / 'tasks', ROOT / 'deployment.json', CONFIG, CONFIG / 'config.yaml', CONFIG / 'server.crt', CONFIG / 'server.key', BINARY, UNIT, RC, LOGROTATE):
        if path.is_symlink():
            raise RuntimeError('unsafe_symlink')
        if path.exists() and path.stat().st_mode & 0o022:
            raise RuntimeError('unsafe_permissions')
    # Unknown overrides can change ExecStart, credentials or security policy.
    if Path(str(UNIT) + '.d').exists() or Path('/etc/conf.d/hysteria-server').exists():
        raise RuntimeError('unknown_service_override')
    metadata = ROOT / 'deployment.json'
    exists = any(p.exists() for p in (CONFIG, BINARY, UNIT, RC))
    if not exists:
        return {'action': 'install', 'init': kind}, None
    if CONFIG.exists() and any(path.is_symlink() for path in CONFIG.rglob('*')):
        raise RuntimeError('unsafe_symlink')
    if not (CONFIG / 'config.yaml').is_file():
        raise RuntimeError('unknown_existing_deployment')
    import yaml
    config = yaml.safe_load((CONFIG / 'config.yaml').read_text())
    if not isinstance(config, dict):
        raise RuntimeError('invalid_existing_config')
    managed = metadata.is_file()
    legacy = False
    if not managed:
        cert = CONFIG / 'server.crt'
        subject = run(['openssl', 'x509', '-in', str(cert), '-noout', '-subject']).stdout if cert.is_file() else ''
        # Legacy ownership is conservative: require the generated unit, cert,
        # config and binary paths together, not CN alone.
        unit = UNIT if kind == 'systemd' else RC
        text = unit.read_text() if unit.is_file() else ''
        legacy = ('miao-hysteria' in subject and str(BINARY) in text
                  and str(CONFIG / 'config.yaml') in text and BINARY.is_file()
                  and config.get('masquerade', {}).get('proxy', {}).get('url') == 'https://www.bing.com/')
        if not legacy:
            raise RuntimeError('third_party_deployment_protected')
    if config.get('tls', {}).get('cert') != str(CONFIG / 'server.crt') or config.get('tls', {}).get('key') != str(CONFIG / 'server.key'):
        raise RuntimeError('unsupported_certificate_paths')
    auth = config.get('auth', {})
    obfs = config.get('obfs', {})
    if auth.get('type') != 'password' or not isinstance(auth.get('password'), str) or not auth['password']:
        raise RuntimeError('unsupported_existing_auth')
    if obfs.get('type') not in ('gecko', 'salamander'):
        raise RuntimeError('unsupported_existing_obfs')
    if not isinstance(obfs.get(obfs['type'], {}).get('password'), str):
        raise RuntimeError('invalid_existing_obfs')
    try:
        port = int(str(config['listen']).rsplit(':', 1)[1])
    except (KeyError, ValueError, IndexError):
        raise RuntimeError('unsupported_existing_listener')
    if port != req['listen_port']:
        raise RuntimeError('existing_port_mismatch')
    if managed:
        meta = json.loads(metadata.read_text())
        if meta.get('config_sha256') != hashlib.sha256((CONFIG / 'config.yaml').read_bytes()).hexdigest():
            raise RuntimeError('managed_config_changed')
    # Preserve a healthy legacy deployment too. Migration is explicit only when needed.
    san = run(['openssl', 'x509', '-in', str(CONFIG / 'server.crt'), '-noout', '-ext', 'subjectAltName'], check=False).stdout
    action = 'migrate' if legacy and 'DNS:miao-hysteria' not in san else ('recover' if running(kind) else 'repair')
    return {'action': action, 'init': kind, 'legacy': legacy}, config


def result_node(req, config, deployment_id):
    cert_path = Path(config['tls']['cert'])
    # Embed the exact trusted certificate; sing-box verifies it rather than insecure=true.
    cert = cert_path.read_text()
    if '-----BEGIN CERTIFICATE-----' not in cert or len(cert) > 65536:
        raise RuntimeError('invalid_certificate')
    subject = run(['openssl', 'x509', '-in', str(cert_path), '-noout', '-subject', '-nameopt', 'RFC2253']).stdout
    # Our own certificate has this name. Custom certificates require explicit user import.
    if 'CN=miao-hysteria' not in subject:
        raise RuntimeError('unsupported_certificate_name')
    return {'type': 'hysteria2', 'tag': req.get('name') or 'vps-' + deployment_id[:12],
            'server': req['node_host'], 'server_port': req['node_port'],
            'password': config['auth']['password'],
            'obfs': {'type': config['obfs']['type'], 'password': config['obfs'][config['obfs']['type']]['password']},
            'tls': {'enabled': True, 'server_name': 'miao-hysteria', 'certificate': [cert], 'insecure': False}}


def download(url, path, prefix, progress=None):
    for source in ([url, prefix + url] if prefix else [url]):
        for attempt in range(3):
            try:
                with urllib.request.urlopen(source, timeout=30) as response, open(path, 'wb') as out:
                    deadline = time.monotonic() + 180
                    size = 0
                    total = int(response.headers.get('Content-Length', '0'))
                    last_update = 0
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > 128 * 1024 * 1024 or time.monotonic() > deadline:
                            raise RuntimeError('download_limit')
                        out.write(chunk)
                        if progress and time.monotonic() - last_update > 1:
                            progress(size, total, 'direct' if source == url else 'proxy')
                            last_update = time.monotonic()
                    if progress:
                        progress(size, total, 'direct' if source == url else 'proxy')
                return
            except Exception:
                if attempt < 2:
                    time.sleep(attempt + 1)
    raise RuntimeError('download_failed')


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def restore(task, journal):
    kind = journal['init']
    service('stop', kind, False)
    if running(kind):
        raise RuntimeError('cannot_stop_service')
    for index, path in enumerate((CONFIG, BINARY, UNIT, RC, ROOT / 'deployment.json', LOGROTATE)):
        remove(path)
        old = task / 'backup' / str(index)
        if old.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            if old.is_dir():
                shutil.copytree(old, path)
            else:
                shutil.copy2(old, path)
    remove(CONFIG.with_name('hysteria.miao-' + task.name))
    remove(BINARY.with_name('hysteria.miao-' + task.name))
    reload(kind)
    # Restore availability even if restoring autostart fails.
    error = None
    try:
        if (UNIT if kind == 'systemd' else RC).exists():
            autostart(journal['enabled'], kind)
        else:
            if kind == 'systemd':
                service('disable', kind, False)
            else:
                run(['rc-update', 'del', SERVICE, 'default'], check=False)
            if enabled(kind):
                raise RuntimeError('autostart_restore_failed')
    except Exception as exc:
        error = exc
    if journal['running']:
        service('restart', kind)
        stable(kind)
    if error:
        raise error


def execute(req, task, reconcile=False):
    def stage(value, **extra):
        atomic(task / 'status.json', {'stage': value, 'updated': int(time.time()), **extra})
    with open(ROOT / 'deploy.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('host_deployment_busy')
        # Repair an interrupted previous activation before allowing new work.
        for journal_path in sorted((ROOT / 'tasks').glob('*/journal.json')):
            old = json.loads(journal_path.read_text())
            if old['phase'] in ('activating', 'rolling_back'):
                old['phase'] = 'rolling_back'
                atomic(journal_path, old)
                restore(journal_path.parent, old)
                old['phase'] = 'rolled_back'
                atomic(journal_path, old)
                atomic(journal_path.parent / 'status.json', {'stage': 'rolled_back'})
                if journal_path.parent == task:
                    return
        stage('checking')
        info, config = inspect(req)
        kind = info['init']
        deployment_id = (json.loads((ROOT / 'deployment.json').read_text()).get('id')
                         if (ROOT / 'deployment.json').exists() else secrets.token_hex(16))
        if config and info['action'] != 'migrate':
            if info['action'] == 'repair':
                stage('repairing')
                # No config rewrite and no credential rotation for repair.
                service('restart', kind)
                stable(kind)
            node = result_node(req, config, deployment_id)
            stage('remote_ready', node=node, deployment_id=deployment_id)
            return
        if reconcile:
            stage('error', error='interrupted_before_activation')
            return
        if shutil.disk_usage(ROOT).free < 256 * 1024 * 1024 or shutil.disk_usage('/etc').free < 32 * 1024 * 1024 or shutil.disk_usage('/usr/local').free < 128 * 1024 * 1024:
            raise RuntimeError('insufficient_disk_space')
        # Refuse occupied ports before stopping anything; parsing ss is only preflight,
        # bind/start checks remain authoritative.
        sockets = run(['ss', '-H', '-lun']).stdout
        if not config and any(line.split()[3].rsplit(':', 1)[-1] == str(req['listen_port']) for line in sockets.splitlines() if len(line.split()) > 3):
            raise RuntimeError('udp_port_in_use')
        stage('downloading')
        arch = 'amd64' if platform.machine() == 'x86_64' else 'arm64'
        asset = 'hysteria-linux-' + arch
        base = 'https://github.com/apernet/hysteria/releases/download/app/' + VERSION + '/'
        binary = task / 'binary'
        download(base + asset, binary, req.get('download_proxy', ''),
                 lambda size, total, source: stage('downloading', downloaded=size, total=total, source=source))
        hashes = task / 'hashes.txt'
        download(base + 'hashes.txt', hashes, req.get('download_proxy', ''))
        stage('verifying_download')
        expected = [line.split()[0] for line in hashes.read_text().splitlines()
                    if len(line.split()) == 2 and line.split()[1].lstrip('*') in ('build/' + asset, asset)]
        if len(expected) != 1 or hashlib.sha256(binary.read_bytes()).hexdigest() != expected[0]:
            raise RuntimeError('checksum_mismatch')
        binary.chmod(0o755)
        if VERSION.lstrip('v') not in run([str(binary), 'version']).stdout:
            raise RuntimeError('binary_version_mismatch')
        stage('preparing')
        new_config = task / 'config'
        if config:
            shutil.copytree(CONFIG, new_config)
        else:
            new_config.mkdir(mode=0o700)
        run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-sha256', '-days', '3650',
             '-keyout', str(new_config / 'server.key'), '-out', str(new_config / 'server.crt'),
             '-subj', '/CN=miao-hysteria', '-addext', 'subjectAltName=DNS:miao-hysteria'])
        (new_config / 'server.key').chmod(0o600)
        if config:
            # Preserve legacy auth, obfs and custom configuration during the
            # certificate/binary migration. Existing Miao clients use insecure TLS.
            config['tls'] = {'cert': str(CONFIG / 'server.crt'), 'key': str(CONFIG / 'server.key')}
        else:
            config = {'listen': ':' + str(req['listen_port']),
                      'tls': {'cert': str(CONFIG / 'server.crt'), 'key': str(CONFIG / 'server.key')},
                      'auth': {'type': 'password', 'password': secrets.token_hex(24)},
                      'obfs': {'type': 'gecko', 'gecko': {'password': secrets.token_hex(24)}},
                      'masquerade': {'type': 'proxy', 'proxy': {'url': 'https://www.bing.com/', 'rewriteHost': True}}}
        atomic(new_config / 'config.yaml', config)
        stage('backing_up')
        backup = task / 'backup'
        backup.mkdir(mode=0o700)
        for index, path in enumerate((CONFIG, BINARY, UNIT, RC, ROOT / 'deployment.json', LOGROTATE)):
            if path.exists():
                if path.is_dir():
                    shutil.copytree(path, backup / str(index))
                else:
                    shutil.copy2(path, backup / str(index))
        journal = {'phase': 'activating', 'init': kind, 'running': running(kind), 'enabled': enabled(kind)}
        atomic(task / 'journal.json', journal)
        try:
            stage('activating')
            # /etc and /usr/local staging are on their destination filesystems.
            config_stage = CONFIG.with_name('hysteria.miao-' + task.name)
            shutil.copytree(new_config, config_stage)
            binary_stage = BINARY.with_name('hysteria.miao-' + task.name)
            BINARY.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, binary_stage)
            # A dedicated account avoids running the proxy as root.
            account = run(['id', '-u', 'miao-hysteria'], check=False)
            if account.returncode == 0 and account.stdout.strip() == '0':
                raise RuntimeError('unsafe_service_account')
            if account.returncode != 0:
                if shutil.which('useradd'):
                    run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/bin/false', 'miao-hysteria'])
                else:
                    run(['addgroup', '-S', 'miao-hysteria'])
                    run(['adduser', '-S', '-D', '-H', '-G', 'miao-hysteria', '-s', '/bin/false', 'miao-hysteria'])
            for path in [config_stage, *config_stage.rglob('*')]:
                shutil.chown(path, user='miao-hysteria', group='miao-hysteria')
            service('stop', kind, False)
            if running(kind):
                raise RuntimeError('cannot_stop_service')
            remove(CONFIG)
            os.replace(config_stage, CONFIG)
            os.replace(binary_stage, BINARY)
            if kind == 'systemd':
                unit = '''[Unit]\nDescription=Miao Hysteria2\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=miao-hysteria\nGroup=miao-hysteria\nExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml\nRestart=on-failure\nRestartSec=5\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n[Install]\nWantedBy=multi-user.target\n'''
                UNIT.write_text(unit)
                UNIT.chmod(0o644)
            else:
                RC.write_text('''#!/sbin/openrc-run\nname="Miao Hysteria2"\ncommand="/usr/local/bin/hysteria"\ncommand_args="server -c /etc/hysteria/config.yaml"\ncommand_user="miao-hysteria:miao-hysteria"\ncommand_background=true\npidfile="/run/hysteria-server.pid"\noutput_log="/var/log/hysteria-server.log"\nerror_log="/var/log/hysteria-server.log"\ndepend() { need net; }\n''')
                RC.chmod(0o755)
                if not LOGROTATE.exists():
                    LOGROTATE.parent.mkdir(parents=True, exist_ok=True)
                    LOGROTATE.write_text('/var/log/hysteria-server.log {\n daily\n rotate 7\n size 10M\n missingok\n notifempty\n compress\n copytruncate\n}\n')
                    LOGROTATE.chmod(0o644)
                if req['listen_port'] < 1024:
                    run(['setcap', 'cap_net_bind_service=+ep', str(BINARY)])
            reload(kind)
            autostart(True, kind)
            service('restart', kind)
            stage('checking_service')
            stable(kind)
            verify_listener(kind, req['listen_port'])
            atomic(ROOT / 'deployment.json', {'id': deployment_id, 'version': VERSION,
                   'config_sha256': hashlib.sha256((CONFIG / 'config.yaml').read_bytes()).hexdigest()})
            node = result_node(req, config, deployment_id)
            journal['phase'] = 'healthy'
            atomic(task / 'journal.json', journal)
            stage('remote_ready', node=node, deployment_id=deployment_id)
            with contextlib.suppress(OSError):
                for artifact in ('binary', 'hashes.txt', 'config'):
                    remove(task / artifact)
                completed = []
                for path in (ROOT / 'tasks').glob('*/journal.json'):
                    try:
                        if json.loads(path.read_text())['phase'] in ('healthy', 'rolled_back'):
                            completed.append(path.parent)
                    except (OSError, ValueError, KeyError):
                        pass
                for old_task in sorted(completed, key=lambda p: p.stat().st_mtime, reverse=True)[2:]:
                    remove(old_task / 'backup')
        except BaseException:
            # After durable commit, publishing/cleanup failure must never roll back
            # a node which the client may already have imported. Reconcile can
            # reconstruct the result from the committed deployment.
            if journal['phase'] == 'healthy':
                raise
            stage('rolling_back')
            journal['phase'] = 'rolling_back'
            atomic(task / 'journal.json', journal)
            try:
                restore(task, journal)
                journal['phase'] = 'rolled_back'
                atomic(task / 'journal.json', journal)
                stage('rolled_back')
            except BaseException:
                stage('recovery_required', backup=str(backup))
            raise


def main():
    os.umask(0o077)
    req = json.loads(base64.b64decode(sys.argv[2]))
    if sys.argv[1] != 'inspect':
        def interrupted(_signal, _frame):
            raise RuntimeError('deployment_interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
    if sys.argv[1] == 'inspect':
        try:
            info, _ = inspect(req)
            print(json.dumps(info))
        except ImportError:
            print(json.dumps({'action': 'dependencies_required'}))
        except Exception as exc:
            code = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            print(json.dumps({'action': 'blocked', 'error': code}))
        return
    task = ROOT / 'tasks' / req['id']
    try:
        atomic(task / 'process.json', {'pid': os.getpid(), 'start': Path('/proc/self/stat').read_text().split()[21]})
        execute(req, task, sys.argv[1] == 'reconcile')
    except BaseException as exc:
        current = json.loads((task / 'status.json').read_text()) if (task / 'status.json').exists() else {}
        journal_path = task / 'journal.json'
        healthy = journal_path.exists() and json.loads(journal_path.read_text()).get('phase') == 'healthy'
        if healthy and current.get('stage') != 'remote_ready':
            atomic(task / 'status.json', {'stage': 'unknown'})
        elif current.get('stage') not in ('rolled_back', 'recovery_required', 'remote_ready'):
            # Only expose fixed error codes, never subprocess stderr or config data.
            code = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            atomic(task / 'status.json', {'stage': 'error', 'error': code})
        if current.get('stage') != 'recovery_required' and not healthy:
            with contextlib.suppress(OSError):
                for artifact in ('binary', 'hashes.txt', 'config'):
                    remove(task / artifact)


if __name__ == '__main__':
    main()
