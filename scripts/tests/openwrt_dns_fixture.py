"""Real dnsmasq plus private procd service fixtures for namespace acceptance.

Only private copies are mounted. No host directories are mounted beneath a
TemporaryDirectory: recursive deletion must never reach original host files.
"""
import fcntl
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import time


def query(server="127.0.0.1", port=53, tcp=False, domain="www.google.com", qtype=1):
    question = b"".join(bytes([len(part)]) + part.encode() for part in domain.split('.')) + b"\0" + struct.pack("!HH", qtype, 1)
    packet = struct.pack("!HHHHHH", 1937, 0x100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET6 if ':' in server else socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((server, port))
        if tcp:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            def read(n):
                data = b""
                while len(data) < n:
                    part = sock.recv(n - len(data))
                    if not part:
                        raise EOFError("DNS closed")
                    data += part
                return data
            answer = read(struct.unpack("!H", read(2))[0])
        else:
            sock.send(packet)
            answer = sock.recv(4096)
    assert answer[:2] == packet[:2] and answer[3] & 15 == 0, answer.hex()
    return answer


def answer_ip(packet):
    # Fixture DNS responses contain exactly one final A RR.
    return socket.inet_ntoa(packet[-4:]) if packet[6:8] != b"\0\0" else None


def alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(') ', 1)[1][0] != 'Z'
    except (FileNotFoundError, ProcessLookupError):
        return False


def terminate(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def dispatch():
    """Small, file-locked procd substitute. Its daemons outlive API processes."""
    directory = Path(os.environ['MIAO_DNS_FIXTURE_DIR'])
    database = directory / 'services.json'
    with (directory / 'services.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        services = json.loads(database.read_text()) if database.exists() else {}
        if sys.argv[1] == 'restart':
            assert sys.argv[2:] == ['fixture']
            if (directory / 'restart-fail').exists():
                sys.exit(1)
            if (directory / 'restart-delay').exists():
                (directory / 'restarting').touch()
                time.sleep(1)
            entry = services.get('dnsmasq', {}).get('instances', {}).get('fixture', {})
            if entry.get('pid') and alive(entry['pid']):
                terminate(entry['pid'])
                deadline = time.monotonic() + 3
                while alive(entry['pid']) and time.monotonic() < deadline:
                    time.sleep(.02)
            command = [os.environ['MIAO_DNSMASQ_BINARY'], '-C', str(directory / 'dnsmasq.conf'), '-k']
            with (directory / 'dnsmasq.log').open('ab') as output:
                proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
            services['dnsmasq'] = {'instances': {'fixture': {'command': command, 'pid': proc.pid, 'running': True}}}
            database.write_text(json.dumps(services))
            sys.exit(0)
        assert sys.argv[1:3] == ['call', 'service']
        method, request = sys.argv[3], json.loads(sys.argv[4])
        name = request.get('name')
        if method == 'set':
            instances = request['instances']
            for entry in instances.values():
                assert entry['respawn'] == ['3600', '1', '5'], 'procd respawn parameters are strings'
                with (directory / 'guard.log').open('ab') as output:
                    proc = subprocess.Popen(entry['command'], env=dict(os.environ, **entry.get('env', {})), stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
                entry.update(pid=proc.pid, running=True)
            services[name] = {'instances': instances}
            database.write_text(json.dumps(services))
            print('{}')
        elif method == 'delete':
            service = services.pop(name, {})
            database.write_text(json.dumps(services))
            for entry in service.get('instances', {}).values():
                if alive(entry['pid']):
                    terminate(entry['pid'])
            print('{}')
        elif method == 'list':
            result = {name: services[name]} if name in services else {}
            for service in result.values():
                for entry in service['instances'].values():
                    entry['running'] = alive(entry['pid'])
            print(json.dumps(result))
        else:
            raise AssertionError(method)


class DNSFixture:
    def __init__(self, directory, binary, mount, external_system_dns=False):
        self.external_system_dns = external_system_dns
        self.trace_process = None
        self.directory = directory / 'dns-fixture'
        self.directory.mkdir()
        self.confdir = self.directory / 'fragments'
        self.confdir.mkdir()
        self.log = self.directory / 'dirty.log'
        self.log.touch()
        private_etc = self.directory / 'etc'
        private_etc.mkdir()
        # Copy only read-only identity/NSS inputs needed by real dnsmasq/libc.
        for name in ['passwd', 'group', 'nsswitch.conf', 'hosts', 'ld.so.cache']:
            source = Path('/etc') / name
            if source.is_file():
                (private_etc / name).write_bytes(source.read_bytes())
        if Path('/etc/alternatives').is_dir():
            shutil.copytree('/etc/alternatives', private_etc / 'alternatives', symlinks=True)
        resolvers = 'nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n' if external_system_dns else 'nameserver 127.0.0.1\n'
        (private_etc / 'resolv.conf').write_text(resolvers + 'search fixture.ts.net lan\n')
        (private_etc / 'openwrt_release').write_text("DISTRIB_ID='OpenWrt'\n")
        init = private_etc / 'init.d'
        init.mkdir()
        helper = Path(__file__).resolve()
        wrapper = f'#!{sys.executable}\nimport runpy, traceback\ntry:\n runpy.run_path({str(helper)!r}, run_name="__main__")\nexcept Exception:\n traceback.print_exc(file=open({str(self.directory / "procd-errors.log")!r}, "a"))\n raise\n'
        (init / 'dnsmasq').write_text(wrapper)
        (init / 'dnsmasq').chmod(0o755)
        tools = self.directory / 'bin'
        tools.mkdir()
        (tools / 'ubus').write_text(wrapper)
        (tools / 'ubus').chmod(0o755)
        if os.environ.get('MIAO_DNS_TRACE'):
            nft_binary = shutil.which('nft')
            (tools / 'nft').write_text(f'''#!{sys.executable}
import sys, subprocess, os
if sys.argv[1:3] == ["monitor", "trace"]:
    os.execv({nft_binary!r}, [{nft_binary!r}] + sys.argv[1:])
r = subprocess.run([{nft_binary!r}] + sys.argv[1:], capture_output=True)
if sys.argv[-1].endswith('/dns-system.nft') and '-c' not in sys.argv:
    snapshot = subprocess.run([{nft_binary!r}, '-j', '-a', 'list', 'ruleset'], capture_output=True)
    open({str(self.directory / 'ruleset.json')!r}, 'wb').write(snapshot.stdout)
sys.stdout.buffer.write(r.stdout)
sys.stderr.buffer.write(r.stderr)
sys.exit(r.returncode)
''')
            (tools / 'nft').chmod(0o755)
        os.environ['PATH'] = str(tools) + os.pathsep + os.environ['PATH']
        os.environ['MIAO_DNS_FIXTURE_DIR'] = str(self.directory)
        os.environ['MIAO_DNSMASQ_BINARY'] = binary
        mount(private_etc, '/etc', flags=4096)
        (self.directory / 'wan-resolv').write_text('nameserver 192.0.2.2\n')
        (self.directory / 'leases').write_text(f'{int(time.time())+86400} 02:00:00:00:00:77 192.168.77.117 laptop *\n')
        (self.directory / 'dnsmasq.conf').write_text(
            f'port=53\nuser=root\ngroup=root\n'
            f'bind-dynamic\nlocal-service\nno-hosts\nstop-dns-rebind\ndomain=lan\nlocal=/lan/\nexpand-hosts\n'
            f'dhcp-range=192.168.77.100,192.168.77.150,12h\ndhcp-leasefile={self.directory}/leases\n'
            f'host-record=printer.lan,192.168.77.42\nmin-cache-ttl=3600\n'
            f'resolv-file={self.directory}/wan-resolv\nconf-dir={self.confdir}\n')
        subprocess.run(['/etc/init.d/dnsmasq', 'restart', 'fixture'], check=True)
        if external_system_dns:
            # Model Tailscale's anti-spoof input chains. NAT replies arriving on
            # loopback need a narrowly scoped, owned exception before these drops.
            rules = '''table ip tailscale_fixture4 {
chain ts-input { iifname lo ip saddr 100.64.0.0/10 drop; }
chain input { type filter hook input priority -1; policy accept; jump ts-input; }
}
table ip6 tailscale_fixture6 {
chain ts-input { iifname lo ip6 saddr fd7a:115c:a1e0::/48 drop; }
chain input { type filter hook input priority -1; policy accept; jump ts-input; }
}
'''
            subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True, capture_output=True)
        if os.environ.get('MIAO_DNS_TRACE'):
            rules = '''table inet dns_trace_fixture {
chain output { type filter hook output priority -301; policy accept;
meta nfproto ipv6 meta l4proto udp meta nftrace set 1
}
chain state { type filter hook output priority -198; policy accept;
meta nfproto ipv6 meta l4proto udp ct state new counter comment "ct-new"
meta nfproto ipv6 meta l4proto udp ct state untracked counter comment "ct-untracked"
meta nfproto ipv6 meta l4proto udp ct state invalid counter comment "ct-invalid"
}
}
'''
            subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
            with (self.directory / 'trace.log').open('wb') as output:
                self.trace_process = subprocess.Popen(['stdbuf', '-oL', 'nft', 'monitor', 'trace'], stdout=output, stderr=output)
        try:
            self.wait_dns('69.171.235.22')
        except BaseException:
            self.close()
            raise

    def wait_dns(self, expected, timeout=8):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if answer_ip(query()) == expected:
                    return
            except (OSError, AssertionError):
                pass
            if time.monotonic() > deadline:
                raise AssertionError(f'DNS did not become {expected}; ' + (self.directory / 'dnsmasq.log').read_text()[-1200:])
            time.sleep(.05)

    def protected(self):
        for tcp in [False, True]:
            assert answer_ip(query(tcp=tcp)) == '8.8.4.4'
            assert answer_ip(query(port=6263, tcp=tcp)) == '8.8.4.4'
            assert query(tcp=tcp, qtype=28)[6:8] == b'\0\0', 'poisoned AAAA leaked through the IPv4-only public resolver'
            assert answer_ip(query(domain='printer.lan', tcp=tcp)) == '192.168.77.42'
            assert answer_ip(query(domain='laptop.lan', tcp=tcp)) == '192.168.77.117'
            assert answer_ip(query(domain='router.fixture.ts.net', tcp=tcp)) == '100.64.0.77', 'MagicDNS private addresses were blocked or sent to public DNS'
            assert query(domain='router.fixture.ts.net', tcp=tcp, qtype=28)[-16:] == socket.inet_pton(socket.AF_INET6, 'fd7a:115c:a1e0::77'), 'MagicDNS private AAAA was filtered'
        assert len(list(self.confdir.glob('miao-*.conf'))) == 1
        if self.external_system_dns:
            for server in ['100.100.100.100', 'fd7a:115c:a1e0::53']:
                for tcp in [False, True]:
                    assert answer_ip(query(server, tcp=tcp)) == '8.8.4.4', 'system resolver bypassed protected DNS'
                    assert query(server, tcp=tcp, qtype=28)[6:8] == b'\0\0'

    def restored(self, runtime):
        self.wait_dns('69.171.235.22', timeout=12)
        assert not list(self.confdir.glob('miao-*.conf'))
        deadline = time.monotonic() + 4
        while (runtime / 'dns-ownership.json').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert not (runtime / 'dns-ownership.json').exists()
        assert answer_ip(query(domain='laptop.lan')) == '192.168.77.117'
        if self.external_system_dns:
            tables = subprocess.check_output(['nft', '-j', 'list', 'tables'], text=True)
            assert 'miao_dns_' not in tables, 'system DNS redirection survived restoration'
            rules = subprocess.check_output(['nft', '-j', 'list', 'ruleset'], text=True)
            assert 'miao-dns:' not in rules, 'owned DNS reply exception survived restoration'

    def close(self):
        if self.trace_process:
            self.trace_process.terminate()
            self.trace_process.wait()
        database = self.directory / 'services.json'
        if database.exists():
            for service in json.loads(database.read_text()).values():
                for entry in service['instances'].values():
                    if alive(entry['pid']):
                        terminate(entry['pid'])


if __name__ == '__main__':
    dispatch()
