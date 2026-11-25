"""Root-only acceptance with real Miao/sing-box in private mount/network namespaces.

python3 scripts/tests/openwrt_runtime_test.py --binary /absolute/path/to/miao
All endpoints are local fixtures. The caller's HOME, routes and firewall stay intact.
"""
import argparse
import array
import ctypes
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from openwrt_dns_fixture import DNSFixture, query as dns_query, answer_ip

BINARY = os.environ.get("MIAO_TEST_BINARY")
SIMULATE_FW3 = False
SIMULATE_FW4 = False
DNSMASQ_BINARY = None
EXTERNAL_SYSTEM_DNS = False
PRIVATE_SUBSCRIPTION = None
IP = shutil.which("ip")
TARGET = "203.0.113.10"
DNS_TARGET = "8.8.4.4"
LIBC = ctypes.CDLL(None, use_errno=True)


def legacy_fw3():
    fw3, fw4 = shutil.which("fw3"), shutil.which("fw4")
    return bool(fw3 and (not fw4 or not os.path.samefile(fw3, fw4)))


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True).strip()


def namespace(flags):
    if LIBC.unshare(flags) != 0:
        raise OSError(ctypes.get_errno(), "unshare")


def mount(source, target, kind=None, flags=0):
    LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    value = lambda text: str(text).encode() if text is not None else None
    if LIBC.mount(value(source), value(target), value(kind), flags, None) != 0:
        raise OSError(ctypes.get_errno(), "mount", str(target))


def receive(sock, count):
    result = b""
    while len(result) < count:
        data = sock.recv(count - len(result))
        if not data:
            raise EOFError("socket closed")
        result += data
    return result


def tap(name):
    descriptor = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
    fcntl.ioctl(descriptor, 0x400454CA, struct.pack('16sH22x', name.encode(), 0x1002))
    return descriptor


def dns_answer(query, target=DNS_TARGET):
    # Preserve the full question and return one A record, without public DNS.
    end = 12
    while query[end]:
        end += 1 + query[end]
    # Discard EDNS OPT records from the query's additional section.
    question = query[12:end + 5]
    if question[-4:-2] == b'\x00\x1c':
        ipv6 = '2001::1' if target == '69.171.235.22' else 'fd7a:115c:a1e0::77' if target == '100.64.0.77' else '2606:4700:4700::1111'
        return query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ipv6)
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(target)


def http_reply(sock, body):
    data = b""
    while b"\r\n\r\n" not in data:
        part = sock.recv(4096)
        if not part:
            raise EOFError("HTTP peer closed")
        data += part
        if len(data) > 16384:
            raise ValueError("unexpected HTTP request")
    sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_wan(ready, slow_flag, server_address):
    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(10)
            version, count = receive(sock, 2)
            assert version == 5
            receive(sock, count)
            sock.sendall(b"\x05\x00")
            version, command, _, family = receive(sock, 4)
            if family == 1:
                receive(sock, 4)
            elif family == 3:
                receive(sock, receive(sock, 1)[0])
            else:
                receive(sock, 16)
            port = struct.unpack("!H", receive(sock, 2))[0]
            sock.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(server_address) + struct.pack("!H", 19091 if command == 3 else 0))
            if command == 3:
                try:
                    while sock.recv(1024):
                        pass
                except TimeoutError:
                    pass
            elif port == 53:
                query = receive(sock, struct.unpack("!H", receive(sock, 2))[0])
                change = slow_flag.parent / 'dns-fixture/policy-change'
                if change.exists():
                    directive = change.read_text()
                    change.unlink()
                    with (change.parent / 'dnsmasq.conf').open('a') as output:
                        output.write(directive)
                answer = dns_answer(query)
                sock.sendall(struct.pack("!H", len(answer)) + answer)
            else:
                http_reply(sock, b"via-proxy")

    class SocksUDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            family = data[3]
            end = 8 if family == 1 else 5 + data[4] if family == 3 else 20
            port = struct.unpack("!H", data[end:end + 2])[0]
            header, payload = data[:end + 2], data[end + 2:]
            # Some SOCKS servers accept UDP ASSOCIATE but silently drop DNS.
            # Remote name resolution must also work through TCP-only proxies.
            if port == 53:
                return
            sock.sendto(header + b"via-proxy-udp:" + payload, self.client_address)

    class Direct(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            http_reply(self.request, b"via-direct")

    class DirectUDP(socketserver.BaseRequestHandler):
        def handle(self):
            payload, sock = self.request
            sock.sendto(b"via-direct-udp:" + payload, self.client_address)

    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            payload, sock = self.request
            sock.sendto(dns_answer(payload), self.client_address)

    class DirtyDNS(socketserver.BaseRequestHandler):
        def handle(self):
            payload, sock = self.request
            with (slow_flag.parent / 'dns-fixture/dirty.log').open('ab') as output:
                output.write(b'query\n')
            sock.sendto(dns_answer(payload, '69.171.235.22'), self.client_address)

    class MagicDNS(socketserver.BaseRequestHandler):
        def handle(self):
            payload, sock = self.request
            sock.sendto(dns_answer(payload, '100.64.0.77'), self.client_address)

    class Slow(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(4096)
            slow_flag.touch()
            time.sleep(25)

    servers = [TCPServer((server_address, 19090), Socks), UDPServer((server_address, 19091), SocksUDP),
               TCPServer((TARGET, 18080), Direct), UDPServer((TARGET, 18081), DirectUDP),
               UDPServer(("223.5.5.5", 53), DNS), TCPServer((server_address, 18090), Slow)]
    if DNSMASQ_BINARY:
        servers.append(UDPServer((server_address, 53), DirtyDNS))
        if server_address == '192.0.2.2':
            servers.append(UDPServer(('100.100.100.100', 53), MagicDNS))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    os.write(ready, b"R")
    while True:
        signal.pause()


def request_payload(operation):
    if operation == 'dns_frontend':
        assert answer_ip(dns_query('192.168.77.1')) == DNS_TARGET
        assert answer_ip(dns_query('192.168.77.1', tcp=True)) == DNS_TARGET
        return 'frontend-ok'
    if operation == "tcp":
        with socket.create_connection((TARGET, 18080), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: miao.test\r\n\r\n")
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            return response.split(b"\r\n\r\n", 1)[1].decode()
    if operation == "dns_tcp":
        query = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + b"\x04miao\x04test\x00" + struct.pack("!HH", 1, 1)
        with socket.create_connection(("1.1.1.1", 53), timeout=5) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            response = receive(sock, struct.unpack("!H", receive(sock, 2))[0])
            assert response[:2] == query[:2] and response[-4:] == socket.inet_aton(DNS_TARGET), response
            return "dns-tcp-ok"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        if operation == "dns":
            query = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + b"\x04miao\x04test\x00" + struct.pack("!HH", 1, 1)
            # Public DNS from both router and LAN traverses the TUN DNS hijack path.
            sock.sendto(query, ("1.1.1.1", 53))
            response = sock.recv(4096)
            assert response[:2] == query[:2] and response[-4:] == socket.inet_aton(DNS_TARGET), response
            return "dns-ok"
        sock.sendto(b"test", (TARGET, 18081))
        return sock.recv(4096).decode()


def start_peer(device, address, server, slow_flag=None):
    control, peer_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child_to_parent_r, child_to_parent_w = os.pipe()
    parent_to_child_r, parent_to_child_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            LIBC.prctl(1, signal.SIGKILL)
            namespace(0x40000000)
            control.close()
            descriptor = tap(device)
            peer_control.sendmsg([b'T'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor]))])
            os.close(descriptor)
            peer_control.close()
            os.close(child_to_parent_r)
            os.close(parent_to_child_w)
            os.write(child_to_parent_w, b"N")
            assert os.read(parent_to_child_r, 1) == b"G"
            run(IP, "link", "set", "lo", "up")
            run(IP, "addr", "add", address, "dev", device)
            run(IP, "link", "set", device, "up")
            if server:
                if device == "vpn-test":
                    run(IP, "route", "add", "100.64.0.1/32", "dev", device)
                if EXTERNAL_SYSTEM_DNS and device == 'srv-test':
                    run(IP, 'route', 'add', '100.64.0.77/32', 'via', '192.0.2.1', 'dev', device)
                addresses = [TARGET, "223.5.5.5"]
                if DNSMASQ_BINARY and device == 'srv-test':
                    addresses.append('100.100.100.100')
                for ip in addresses:
                    run(IP, "addr", "add", ip + "/32", "dev", "lo")
                serve_wan(child_to_parent_w, slow_flag, address.split('/')[0])
            else:
                run(IP, "route", "add", "default", "via", "192.168.77.1")
                os.write(child_to_parent_w, b"R")
                reader = os.fdopen(parent_to_child_r)
                writer = os.fdopen(child_to_parent_w, "w", buffering=1)
                for line in reader:
                    try:
                        writer.write(json.dumps({"result": request_payload(json.loads(line)["op"])}) + "\n")
                    except Exception as error:
                        writer.write(json.dumps({"error": str(error)}) + "\n")
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    os.close(child_to_parent_w)
    os.close(parent_to_child_r)
    peer_control.close()
    _, messages, _, _ = control.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
    descriptors = array.array('i')
    for level, kind, data in messages:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
    control.close()
    assert len(descriptors) == 1
    assert os.read(child_to_parent_r, 1) == b"N"
    return pid, child_to_parent_r, parent_to_child_w, descriptors[0]


class Fixture:
    def __init__(self, directory, binary):
        self.directory, self.binary = directory, binary
        self.runtime = directory / "runtime"
        self.config_path = directory / "config.yaml"
        self.log = directory / "miao.log"
        self.process = None
        self.disable_nftables = False
        self.cookie, self.csrf = "", ""
        # Keep fixture listeners below the ephemeral range used by the DNS probes.
        self.config = {"port": 6162, "mode": "global", "socks_port": 19080,
                       "share": {"base_port": 20000},
                       "tun": {"routing": "policy_route", "lan_interfaces": ["br-test"]},
                       "nodes": [json.dumps({"type": "socks", "tag": "fixture", "server": "192.0.2.2", "server_port": 19090})]}

    def start(self, disable_nftables=None):
        if disable_nftables is not None:
            self.disable_nftables = disable_nftables
        self.config_path.write_text(json.dumps(self.config))
        environment = dict(os.environ)
        environment.update(MIAO_EMBEDDED="ivnc", MIAO_PORT="6162", MIAO_RUNTIME_DIR=str(self.runtime))
        environment.pop("DISABLE_NFTABLES", None)
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]:
            environment.pop(key, None)
        if self.disable_nftables:
            environment["DISABLE_NFTABLES"] = "true"
        with self.log.open("ab") as log:
            self.process = subprocess.Popen([self.binary, "--config", str(self.config_path), "--nopasswd"], env=environment,
                                            stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 8
        while True:
            try:
                response = self.api("POST", "/api/auth/login", {})
                self.csrf = response["data"]["csrf"]
                if not self.api("GET", "/api/status")["data"]["initializing"]:
                    return
            except (OSError, ConnectionError):
                pass
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("Miao panel failed: " + self.log.read_text()[-3000:])
            time.sleep(.05)

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("Miao shutdown timed out")

    def api(self, method, path, body=None, success=True):
        connection = http.client.HTTPConnection("127.0.0.1", 6162, timeout=12)
        headers = {"Host": "127.0.0.1:6162", "Origin": "http://127.0.0.1:6162", "Content-Type": "application/json", "Cookie": self.cookie, "X-Miao-CSRF": self.csrf}
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        cookie = response.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";", 1)[0]
        payload = json.loads(response.read())
        connection.close()
        if success and not payload.get("success"):
            if PRIVATE_SUBSCRIPTION:
                code = re.search(r'\b(?:DNS|FW3|ROUTING|ROUTE|NETWORK|NFT|START|READY)_[A-Z_]+\b', str(payload.get('message', '')))
                raise AssertionError(f"{method} {path}: {code.group() if code else 'failed'}; private diagnostics suppressed")
            raise AssertionError(payload)
        return payload

    def set_routing(self, routing):
        # Simulate host capabilities through the diagnostic environment override.
        # Public configuration no longer asks the user to choose an implementation.
        self.api("PUT", "/api/tun", {"lan_interfaces": ["br-test"]})
        self.sync_config()
        self.close()
        self.start(disable_nftables=routing == "policy_route")

    def sync_config(self):
        # The application persists YAML; use its API rather than adding a PyYAML dependency.
        self.config["mode"] = self.api("GET", "/api/status")["data"]["mode"]
        self.config["tun"] = self.api("GET", "/api/tun")["data"]
        self.config["tun_process"] = self.api("GET", "/api/tun-process")["data"]


def isolated_suite(binary):
    with tempfile.TemporaryDirectory(prefix="miao-runtime-test-") as temporary:
        directory = Path(temporary)
        root = directory / "private-home"
        root.mkdir()
        namespace(0x40020000)  # CLONE_NEWNET | CLONE_NEWNS
        mount(None, "/", flags=0x4000 | (1 << 18))  # recursive private propagation
        mount(root, Path.home(), flags=4096)
        mount("sysfs", "/sys", "sysfs", 2 | 4 | 8)
        os.chdir(directory)  # Isolate the legacy relative data/cache migration too.
        if SIMULATE_FW3 or SIMULATE_FW4:
            tools = directory / "tools"
            tools.mkdir()
            fw3 = tools / "fw3"
            if SIMULATE_FW4:
                fw4 = tools / "fw4"
                fw4.write_text("#!/bin/sh\nexit 0\n")
                fw4.chmod(0o755)
                fw3.symlink_to("fw4")
            else:
                fw3.write_text("#!/bin/sh\nexit 0\n")
                fw3.chmod(0o755)
            os.environ["PATH"] = str(tools) + os.pathsep + os.environ["PATH"]
        run(IP, "link", "set", "lo", "up")
        slow_flag = directory / "subscription-requested"
        peers = []
        wires = {}
        lan_reader = lan_writer = None
        fixture = Fixture(directory, binary)
        dns = None
        try:
            for server, parent, child, address in [
                (True, "wan-test", "srv-test", "192.0.2.2/30"),
                (True, "overlay-test", "vpn-test", "100.64.0.2/32"),
                (False, "br-test", "lan-test", "192.168.77.2/24"),
            ]:
                pid, reader, writer, peer_tap = start_peer(child, address, server, slow_flag)
                peers.append(pid)
                parent_tap = tap(parent)
                wires[parent_tap], wires[peer_tap] = peer_tap, parent_tap
                parent_address = {"wan-test": "192.0.2.1/30", "overlay-test": "100.64.0.1/32", "br-test": "192.168.77.1/24"}[parent]
                run(IP, "addr", "add", parent_address, "dev", parent)
                run(IP, "link", "set", parent, "up")
                os.write(writer, b"G")
                assert os.read(reader, 1) == b"R"
                if not server:
                    lan_reader, lan_writer = os.fdopen(reader), os.fdopen(writer, "w", buffering=1)
                else:
                    os.close(reader)
                    os.close(writer)
            bridge = os.fork()
            if bridge == 0:
                LIBC.prctl(1, signal.SIGKILL)
                while True:
                    readable, _, _ = select.select(list(wires), [], [], 1)
                    for descriptor in readable:
                        packet = os.read(descriptor, 65535)
                        if packet:
                            os.write(wires[descriptor], packet)
            peers.append(bridge)
            run(IP, "route", "add", "default", "via", "192.0.2.2")
            # Overlay endpoints use a separate policy table, like Tailscale.
            run(IP, "route", "add", "100.64.0.2/32", "dev", "overlay-test", "table", "52")
            run(IP, "rule", "add", "priority", "5270", "lookup", "52")
            if EXTERNAL_SYSTEM_DNS:
                run(IP, 'tuntap', 'add', 'dev', 'ts-source', 'mode', 'tun')
                run(IP, 'addr', 'add', '100.64.0.77/32', 'dev', 'ts-source')
                run(IP, 'link', 'set', 'ts-source', 'up')
                run(IP, 'route', 'add', '100.100.100.100/32', 'via', '192.0.2.2', 'dev', 'wan-test', 'src', '100.64.0.77', 'table', '52')
            run(IP, "-4", "rule", "add", "priority", "1234", "from", "192.0.2.77", "lookup", "main")
            baseline_rules = run(IP, "-4", "rule", "show")
            baseline_routes = run(IP, "-4", "route", "show", "table", "all")
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
            if legacy_fw3():
                run("iptables", "-P", "FORWARD", "DROP")

            if DNSMASQ_BINARY:
                if EXTERNAL_SYSTEM_DNS:
                    run(IP, '-6', 'addr', 'add', 'fd7a:115c:a1e0::53/128', 'dev', 'lo')
                dns = DNSFixture(directory, DNSMASQ_BINARY, mount, external_system_dns=EXTERNAL_SYSTEM_DNS)
                fixture.config['nodes'].insert(0, json.dumps({'type': 'socks', 'tag': 'unavailable-first', 'server': '192.0.2.2', 'server_port': 19999}))
                data = Path.home() / '.miao'
                data.mkdir(exist_ok=True)
                (data / 'last_proxy.json').write_text(json.dumps({'group': 'proxy', 'name': 'fixture'}))

            def lan(operation):
                lan_writer.write(json.dumps({"op": operation}) + "\n")
                result = json.loads(lan_reader.readline())
                assert "error" not in result, result
                return result["result"]

            def data_plane():
                assert request_payload("tcp") == "via-proxy"
                assert request_payload("udp") == "via-proxy-udp:test"
                assert request_payload("dns") == "dns-ok"
                assert request_payload("dns_tcp") == "dns-tcp-ok"
                assert lan("tcp") == "via-proxy"
                assert lan("udp") == "via-proxy-udp:test"
                assert lan("dns") == "dns-ok"
                assert lan("dns_tcp") == "dns-tcp-ok"
                if dns:
                    dns.protected()
                    assert lan('dns_frontend') == 'frontend-ok'

            fixture.start()
            assert not fixture.api("GET", "/api/status")["data"]["running"]
            if dns:
                assert answer_ip(dns_query()) == '69.171.235.22'
                assert socket.inet_pton(socket.AF_INET6, '2001::1') in dns_query(qtype=28)
                count = dns.log.stat().st_size
                assert answer_ip(dns_query()) == '69.171.235.22'
                assert dns.log.stat().st_size == count
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                    occupied.bind(('127.0.0.1', 6263))
                    response = fixture.api('POST', '/api/service/start', success=False)
                    assert not response['success'] and 'DNS_PORT_CONFLICT' in response['message'], response
                broken = dns.confdir / 'invalid.conf'
                broken.write_text('invalid-dnsmasq-option\n')
                response = fixture.api('POST', '/api/service/start', success=False)
                assert not response['success'] and 'DNS_CONFIG_INVALID' in response['message'], response
                broken.unlink()
                if EXTERNAL_SYSTEM_DNS:
                    table = 'miao_dns_' + hashlib.sha256(str(fixture.runtime).encode()).hexdigest()[:12]
                    subprocess.run(['nft', '-f', '-'], input=f'table inet {table} {{ comment "fixture-foreign"; }}\n', text=True, check=True, capture_output=True)
                    response = fixture.api('POST', '/api/service/start', success=False)
                    assert not response['success'] and 'DNS_OWNERSHIP_CONFLICT' in response['message']
                    assert 'fixture-foreign' in run('nft', 'list', 'table', 'inet', table)
                    run('nft', 'delete', 'table', 'inet', table)
                assert not Path('/sys/class/net/sing-tun').exists()
                print('PASS cached poisoned DNS, UDP port conflict and dnsmasq syntax preflight', flush=True)
                original = (dns.directory / 'dnsmasq.conf').read_text()
                change = dns.directory / 'policy-change'
                change.write_text('server=192.0.2.2\n')
                response = fixture.api('POST', '/api/service/start', success=False)
                assert not response['success'] and 'DNS_POLICY_CONFLICT' in response['message']
                assert not change.exists(), 'DNS policy race was not exercised'
                assert not (fixture.runtime / 'dns-ownership.json').exists()
                assert not list(dns.confdir.glob('miao-*.conf'))
                (dns.directory / 'dnsmasq.conf').write_text(original)
                change.write_text('# firmware regenerated configuration\n')
            fixture.api("POST", "/api/service/start")
            if dns:
                assert not (dns.directory / 'policy-change').exists()
                print('PASS configuration regeneration is revalidated; competing upstream remains rejected', flush=True)
            automatic = fixture.api("GET", "/api/status")["data"]["runtime"]["routing"]["effective"]
            assert fixture.api("GET", "/api/tun")["data"]["routing"] == "auto"
            data_plane()
            cli_environment = dict(os.environ, MIAO_EMBEDDED='ivnc', MIAO_RUNTIME_DIR=str(fixture.runtime))
            password_reset = subprocess.run([binary, '--config', str(fixture.config_path), 'password', 'set', 'fixture-reset'], env=cli_environment, capture_output=True, text=True, timeout=5)
            assert password_reset.returncode == 0, 'local password command was blocked by the running DNS owner'
            assert fixture.api('GET', '/api/status')['data']['running']
            if dns:
                prepared = json.loads((fixture.runtime / 'config.json').read_text())
                assert prepared['outbounds'][0]['default'] == 'fixture'
                print('PASS saved node is selected before DNS readiness with an unavailable first node', flush=True)
            if dns:
                dns_failure_checks(fixture, dns, data_plane)
            print("PASS first Web start, automatic routing, router/LAN TCP/UDP/DNS:", automatic, flush=True)
            print("PASS remote DNS remains usable when upstream UDP DNS is dropped", flush=True)
            if SIMULATE_FW4:
                assert "MIAO_" not in run("iptables-save", "-t", "filter"), "fw4 alias was misidentified as legacy fw3"
                print("PASS fw3 -> fw4 compatibility alias uses native routing without legacy chains", flush=True)
            if automatic == "nftables":
                fixture.api("PUT", "/api/nodes", {
                    "original_tag": "fixture", "node_type": "socks", "tag": "fixture", "server": "100.64.0.2", "server_port": 19090,
                })
                data_plane()
                fixture.api("POST", "/api/service/stop")
                # Also exercise migration of existing runtime bytes at Start.
                stale = json.loads((fixture.runtime / "config.json").read_text())
                stale["route"]["auto_detect_interface"] = True
                (fixture.runtime / "config.json").write_text(json.dumps(stale))
                fixture.api("POST", "/api/service/start")
                data_plane()
                fixture.sync_config()
                fixture.close()
                fixture.config["nodes"] = [json.dumps({"type": "socks", "tag": "fixture", "server": "100.64.0.2", "server_port": 19090})]
                fixture.start()
                assert fixture.api("GET", "/api/status")["data"]["running"]
                data_plane()
                fixture.api("PUT", "/api/nodes", {
                    "original_tag": "fixture", "node_type": "socks", "tag": "fixture", "server": "192.0.2.2", "server_port": 19090,
                })
                fixture.config["nodes"] = [json.dumps({"type": "socks", "tag": "fixture", "server": "192.0.2.2", "server_port": 19090})]
                data_plane()
                print("PASS overlay upstream policy routes: router/LAN TCP/UDP/DNS, stale Start and manager restart", flush=True)
            if PRIVATE_SUBSCRIPTION:
                class PrivateSubscriptionHandler(socketserver.BaseRequestHandler):
                    def handle(self):
                        self.request.settimeout(5)
                        http_reply(self.request, PRIVATE_SUBSCRIPTION.encode())
                server = TCPServer(("127.0.0.1", 0), PrivateSubscriptionHandler)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                url = f"http://127.0.0.1:{server.server_address[1]}/private-subscription"
                for endpoint, body in [("/api/subs", {"url": url}),
                                       ("/api/subs/content", {"name": "private acceptance", "content": PRIVATE_SUBSCRIPTION})]:
                    fixture.api("POST", endpoint, body)
                    subscriptions = fixture.api("GET", "/api/subs")["data"]
                    assert len(subscriptions) == 1 and subscriptions[0]["node_count"] > 0
                    assert fixture.api("GET", "/api/status")["data"]["running"]
                    data_plane()
                    count = subscriptions[0]["node_count"]
                    fixture.api("DELETE", "/api/subs", {"url": subscriptions[0]["url"]})
                    data_plane()
                    print("PASS private subscription import/restart:", endpoint, "nodes:", count, flush=True)
                server.shutdown()
                server.server_close()

            fixture.set_routing("policy_route")
            data_plane()
            print("PASS automatic policy-routing fallback data plane", flush=True)
            response = fixture.api("PUT", "/api/tun", {"routing": "policy_route", "lan_interfaces": ["missing0"]}, success=not legacy_fw3())
            if legacy_fw3():
                assert not response["success"]
                assert fixture.api("GET", "/api/tun")["data"]["lan_interfaces"] == ["br-test"]
                data_plane()
                print("PASS failed firewall activation restores old running configuration", flush=True)
            else:
                fixture.set_routing("policy_route")
            if legacy_fw3():
                chains = [line.split()[0][1:] for line in run("iptables-save", "-t", "filter").splitlines() if line.startswith(":MIAO_")]
                for chain in chains:
                    run("iptables", "-F", chain)
                time.sleep(1.5)
                assert lan("tcp") == "via-proxy"
                print("PASS fw3 rule recovery after chain flush", flush=True)

            for process_strategy in ["policy_route"] + (["nftables"] if automatic == "nftables" else []):
                fixture.set_routing(process_strategy)
                fixture.api("POST", "/api/tun-process", {"mode": "blacklist", "match": {"names": ["curl"]}, "bypass_action": "bypass"})
                fixture.api("POST", "/api/mode", {"mode": "process"})
                curl = shutil.which("curl")
                assert curl, "curl is required for process matching acceptance"
                assert run(curl, "--noproxy", "*", "-fsS", "--max-time", "5", f"http://{TARGET}:18080/") == "via-direct"
                assert request_payload("tcp") == "via-proxy"
                fixture.api("POST", "/api/tun-process", {"mode": "whitelist", "match": {"names": ["curl"]}})
                assert run(curl, "--noproxy", "*", "-fsS", "--max-time", "5", f"http://{TARGET}:18080/") == "via-proxy"
                assert request_payload("tcp") == "via-direct"
                print("PASS process blacklist and whitelist:", process_strategy, flush=True)
                fixture.api("POST", "/api/mode", {"mode": "global"})
                fixture.config["mode"] = "global"
            fixture.api("POST", "/api/mode", {"mode": "pool"})
            pool = fixture.api("GET", "/api/status")["data"]
            assert pool["running"] and pool["runtime"]["routing"]["effective"] == "none"
            assert not Path("/sys/class/net/sing-tun").exists()
            assert "MIAO_" not in run("iptables-save", "-t", "filter")
            assert request_payload("tcp") == "via-direct"
            if dns:
                dns.restored(fixture.runtime)
            fixture.api("POST", "/api/mode", {"mode": "global"})
            data_plane()
            print("PASS proxy pool skips TUN and restores global routing", flush=True)

            fixture.set_routing("auto")
            for legacy in ["nftables", "policy_route"]:
                fixture.api("PUT", "/api/tun", {"routing": legacy, "lan_interfaces": ["br-test"]})
                assert fixture.api("GET", "/api/tun")["data"]["routing"] == "auto"
                assert fixture.api("GET", "/api/status")["data"]["runtime"]["routing"]["effective"] == automatic
                data_plane()
            fixture.set_routing("policy_route")
            print("PASS legacy manual choices migrate to automatic routing", flush=True)

            fixture.api("POST", "/api/service/stop")
            assert not Path("/sys/class/net/sing-tun").exists()
            assert "MIAO_" not in run("iptables-save", "-t", "filter")
            stale = json.loads((fixture.runtime / "config.json").read_text())
            stale["inbounds"][0]["auto_redirect"] = True
            stale["dns"]["servers"][0]["type"] = "udp"
            (fixture.runtime / "config.json").write_text(json.dumps(stale))
            fixture.api("POST", "/api/service/start")
            prepared = json.loads((fixture.runtime / "config.json").read_text())
            assert not prepared["inbounds"][0]["auto_redirect"]
            assert prepared["dns"]["servers"][0]["type"] == "tcp"
            data_plane()
            fixture.api("POST", "/api/service/stop")
            print("PASS stale runtime configuration cannot restore nftables", flush=True)
            # A SIGKILL cannot run sing-box's own route/nft cleanup.
            for strategy in ["policy_route"] + (["nftables"] if automatic == "nftables" else []):
                fixture.set_routing(strategy)
                fixture.api("POST", "/api/service/start")
                status = fixture.api("GET", "/api/status")["data"]
                os.kill(status["pid"], signal.SIGKILL)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    status = fixture.api("GET", "/api/status")["data"]
                    if status["runtime"]["phase"] == "failed" and run(IP, "-4", "rule", "show") == baseline_rules:
                        break
                    time.sleep(.05)
                current_rules = run(IP, "-4", "rule", "show")
                if current_rules != baseline_rules:
                    print("Crash diagnostics:", strategy, "\nrules:", current_rules, "\nphase:", status["runtime"]["phase"], "\nerror:", (status["runtime"].get("error") or "")[:1000], flush=True)
                    if (fixture.runtime / "network-ownership.json").exists():
                        print("ownership:", (fixture.runtime / "network-ownership.json").read_text(), flush=True)
                assert current_rules == baseline_rules, "crash left TUN policy rules or removed an unrelated rule"
                assert run(IP, "-4", "route", "show", "table", "all") == baseline_routes, "crash left owned routes"
                assert not (fixture.runtime / "network-ownership.json").exists(), "ownership cleanup did not finish"
                if dns:
                    dns.restored(fixture.runtime)
                fixture.api("POST", "/api/service/start")
                data_plane()
                fixture.api("POST", "/api/service/stop")
            print("PASS forced core exit cleanup preserves unrelated rules and permits restart", flush=True)
            for strategy in ["policy_route"] + (["nftables"] if automatic == "nftables" else []):
                fixture.set_routing(strategy)
                fixture.api("POST", "/api/service/start")
                fixture.sync_config()
                fixture.process.kill()
                fixture.process.wait(3)
                deadline = time.monotonic() + 5
                while Path("/sys/class/net/sing-tun").exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                assert not Path("/sys/class/net/sing-tun").exists(), "manager exit left an unmanaged core"
                if dns:
                    dns.restored(fixture.runtime)
                    assert run(IP, "-4", "rule", "show") == baseline_rules, "guard left policy rules before manager restart"
                    assert run(IP, "-4", "route", "show", "table", "all") == baseline_routes, "guard left owned routes before manager restart"
                    assert "MIAO_" not in run("iptables-save", "-t", "filter"), "guard left fw3 rules before manager restart"
                fixture.config["mode"] = "pool"
                fixture.start()
                status = fixture.api("GET", "/api/status")["data"]
                assert status["running"] and status["runtime"]["routing"]["effective"] == "none", json.dumps({
                    'running': status['running'], 'phase': status['runtime']['phase'],
                    'error_code': (status['runtime'].get('error') or '').split(':', 1)[0],
                    'effective': (status['runtime'].get('routing') or {}).get('effective'),
                })
                assert run(IP, "-4", "rule", "show") == baseline_rules
                assert run(IP, "-4", "route", "show", "table", "all") == baseline_routes
                assert "MIAO_" not in run("iptables-save", "-t", "filter"), "pool restart left a dead manager's firewall rules"
                fixture.api("POST", "/api/mode", {"mode": "global"})
                data_plane()
                fixture.api("POST", "/api/service/stop")
            print("PASS forced manager exit and pool restart recover owned resources", flush=True)
            fixture.sync_config()
            fixture.close()
            fixture.start(disable_nftables=True)
            fixture.api("PUT", "/api/tun", {"routing": "auto", "lan_interfaces": ["br-test"]})
            fixture.api("POST", "/api/service/start")
            data_plane()
            assert fixture.api("GET", "/api/status")["data"]["runtime"]["routing"]["effective"] == "policy_route"
            print("PASS DISABLE_NFTABLES mapping captures traffic", flush=True)
            fixture.sync_config()
            fixture.close()
            fixture.start(disable_nftables=False)
            assert fixture.api("GET", "/api/status")["data"]["running"]
            data_plane()
            print("PASS running-state restore and cache strategy migration", flush=True)

            fixture.api("POST", "/api/service/stop")
            fixture.sync_config()
            fixture.close()
            fixture.config["subs"] = ["http://192.0.2.2:18090/slow"]
            for name in ["config.json", "routing.json"]:
                (fixture.runtime / name).unlink(missing_ok=True)
            fixture.start()
            result = []
            worker = threading.Thread(target=lambda: result.append(fixture.api("POST", "/api/service/start", success=False)))
            worker.start()
            deadline = time.monotonic() + 4
            while not slow_flag.exists() and time.monotonic() < deadline:
                time.sleep(.025)
            assert slow_flag.exists(), "slow subscription was not requested"
            began = time.monotonic()
            fixture.api("POST", "/api/service/stop")
            worker.join(2)
            assert time.monotonic() - began < 2 and not worker.is_alive(), "Stop waited behind subscription I/O"
            assert result and not result[0]["success"]
            assert not Path("/sys/class/net/sing-tun").exists()
            assert not fixture.api("GET", "/api/status")["data"]["running"]
            print("PASS cancellation during subscription preparation", flush=True)
            fixture.close()
            fixture.config["subs"] = []
            fixture.start()
            run(IP, "-4", "rule", "add", "priority", "9005", "from", "192.0.2.77", "lookup", "main")
            response = fixture.api("POST", "/api/service/start", success=False)
            assert not response["success"] and "ROUTING_IN_USE" in response["message"]
            assert "9005:" in run(IP, "-4", "rule", "show")
            run(IP, "-4", "rule", "del", "priority", "9005", "from", "192.0.2.77", "lookup", "main")
            fixture.api("POST", "/api/service/start")
            data_plane()
            fixture.api("POST", "/api/service/stop")
            print("PASS conflicting existing policy rules are preserved", flush=True)
        except BaseException:
            if PRIVATE_SUBSCRIPTION:
                print("Private fixture failed; runtime logs suppressed", flush=True)
            elif fixture.log.exists():
                if dns and (dns.directory / 'trace.log').exists():
                    print('DNS trace:', (dns.directory / 'trace.log').read_text()[-14000:], flush=True)
                if dns and (dns.directory / 'ruleset.json').exists():
                    rules = json.loads((dns.directory / 'ruleset.json').read_text())['nftables']
                    print('DNS chain priorities:', json.dumps([i['chain'] for i in rules if 'chain' in i]), flush=True)
                    print('DNS native rules:', json.dumps([i['rule'] for i in rules if 'rule' in i and i['rule']['table'].startswith('miao_dns_')]), flush=True)
                if EXTERNAL_SYSTEM_DNS and (fixture.runtime / 'dns-ownership.json').exists():
                    owner = json.loads((fixture.runtime / 'dns-ownership.json').read_text())
                    table = owner['plan']['system']['table']
                    snapshot = json.loads(run('nft', '-j', '-a', 'list', 'table', 'inet', table))
                    comments = [item['rule'].get('comment') for item in snapshot['nftables'] if 'rule' in item]
                    print('DNS rule identity:', json.dumps({'expected_marker_found': 'miao-dns:' + owner['token'] in comments, 'comment_lengths': [len(comment or '') for comment in comments], 'recorded_handle': owner.get('system_handle'), 'table_handles': [item['table'].get('handle') for item in snapshot['nftables'] if 'table' in item]}), flush=True)
                if dns and (dns.directory / 'procd-errors.log').exists():
                    print('procd fixture errors:', (dns.directory / 'procd-errors.log').read_text()[-3000:], flush=True)
                print("Fixture log tail:\n" + fixture.log.read_text()[-6000:], flush=True)
            raise
        finally:
            fixture.close()
            if dns:
                dns.close()
            for pid in peers:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            for stream in [lan_reader, lan_writer]:
                if stream:
                    stream.close()
            for descriptor in wires:
                os.close(descriptor)


def dns_failure_checks(fixture, dns, data_plane):
    count = dns.log.stat().st_size
    dns.protected()
    assert dns.log.stat().st_size == count, 'protected query raced the WAN resolver'
    if dns.external_system_dns:
        core_pid = fixture.api('GET', '/api/status')['data']['pid']
        run('nft', 'flush', 'chain', 'ip', 'tailscale_fixture4', 'ts-input')
        subprocess.run(['nft', '-f', '-'], input='add rule ip tailscale_fixture4 ts-input iifname lo ip saddr 100.64.0.0/10 drop\n', text=True, check=True, capture_output=True)
        deadline = time.monotonic() + 9
        while True:
            try:
                dns.protected()
                break
            except (OSError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
        assert fixture.api('GET', '/api/status')['data']['pid'] == core_pid
        print('PASS DNS reply exception recovers after Tailscale chain reload', flush=True)
        table = 'miao_dns_' + hashlib.sha256(str(fixture.runtime).encode()).hexdigest()[:12]
        snapshot = json.loads(run('nft', '-j', '-a', 'list', 'table', 'inet', table))
        handle = next(item['table']['handle'] for item in snapshot['nftables'] if 'table' in item)
        run('nft', 'delete', 'table', 'inet', 'handle', str(handle))
        subprocess.run(['nft', '-f', '-'], input=f'table inet {table} {{ comment "fixture-foreign-replacement"; }}\n', text=True, check=True, capture_output=True)
        response = fixture.api('POST', '/api/service/stop', success=False)
        assert not response['success'] and 'DNS_OWNERSHIP_CONFLICT' in response['message']
        assert fixture.api('GET', '/api/status')['data']['running']
        assert 'fixture-foreign-replacement' in run('nft', 'list', 'table', 'inet', table)
        run('nft', 'delete', 'table', 'inet', table)
        fixture.api('POST', '/api/service/stop')
        dns.restored(fixture.runtime)
        fixture.api('POST', '/api/service/start')
        data_plane()
        print('PASS replaced system DNS table is preserved; retained core permits recovery', flush=True)
    owned = next(dns.confdir.glob('miao-*.conf'))
    original = owned.read_text()
    owned.write_text(original + '# administrator change\n')
    response = fixture.api('POST', '/api/service/stop', success=False)
    assert not response['success'] and 'DNS_OWNERSHIP_CONFLICT' in response['message']
    assert fixture.api('GET', '/api/status')['data']['running']
    assert owned.read_text() == original + '# administrator change\n'
    owned.write_text(original)
    fixture.api('POST', '/api/service/stop')
    dns.restored(fixture.runtime)
    fixture.api('POST', '/api/service/start')
    failure = dns.directory / 'restart-fail'
    failure.touch()
    response = fixture.api('POST', '/api/service/stop', success=False)
    assert not response['success'] and 'DNS_SERVICE_FAILED' in response['message']
    assert fixture.api('GET', '/api/status')['data']['running'], 'DNS restore failure killed the live core'
    assert answer_ip(dns_query()) == DNS_TARGET
    failure.unlink()
    fixture.api('POST', '/api/service/stop')
    dns.restored(fixture.runtime)
    failure.touch()
    response = fixture.api('POST', '/api/service/start', success=False)
    assert not response['success'] and 'DNS_SERVICE_FAILED' in response['message']
    retained = fixture.api('GET', '/api/status')['data']
    assert retained['running'] and retained['runtime']['phase'] == 'ready', 'startup rollback failure hid the retained core'
    failure.unlink()
    os.kill(retained['pid'], signal.SIGKILL)
    dns.restored(fixture.runtime)
    fixture.api('POST', '/api/service/stop')
    (dns.directory / 'restart-delay').touch()
    (dns.directory / 'restarting').unlink(missing_ok=True)
    responses = []
    worker = threading.Thread(target=lambda: responses.append(fixture.api('POST', '/api/service/start', success=False)))
    worker.start()
    deadline = time.monotonic() + 5
    while not (dns.directory / 'restarting').exists() and time.monotonic() < deadline:
        time.sleep(.02)
    assert (dns.directory / 'restarting').exists()
    fixture.api('POST', '/api/service/stop')
    worker.join(6)
    assert responses and not responses[0]['success'] and not worker.is_alive()
    (dns.directory / 'restart-delay').unlink()
    dns.restored(fixture.runtime)
    fixture.api('POST', '/api/service/start')
    data_plane()
    # WAN updates made while Miao is active must be used on restoration, rather
    # than restoring an obsolete snapshot of resolv-file.
    (dns.directory / 'wan-resolv').write_text('nameserver 223.5.5.5\n')
    fixture.api('POST', '/api/service/stop')
    dns.wait_dns(DNS_TARGET)
    assert not list(dns.confdir.glob('miao-*.conf'))
    (dns.directory / 'wan-resolv').write_text('nameserver 192.0.2.2\n')
    run('/etc/init.d/dnsmasq', 'restart', 'fixture')
    dns.restored(fixture.runtime)
    fixture.api('POST', '/api/service/start')
    data_plane()
    print('PASS DNS restoration follows updated WAN resolv-file', flush=True)
    print('PASS protected Google DNS, DHCP names, ownership conflict, failed restoration and cancellation', flush=True)


def host_snapshot():
    rules = run("iptables-save")
    stable = "\n".join(line for line in rules.splitlines() if line.startswith(("-A ", "*")))
    return (hashlib.sha256(stable.encode()).hexdigest(), run(IP, "-4", "rule"), run(IP, "-4", "route", "show", "table", "all"))


@unittest.skipUnless(BINARY and os.geteuid() == 0 and IP, "requires MIAO_TEST_BINARY, root, iproute2 and namespace support")
class RuntimeAcceptance(unittest.TestCase):
    def test_isolated_router_and_lan(self):
        before = host_snapshot()
        child = os.fork()
        if child == 0:
            try:
                LIBC.prctl(1, signal.SIGKILL)
                isolated_suite(str(Path(BINARY).resolve()))
            except BaseException:
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertEqual(host_snapshot(), before, "host routes or firewall changed")
        self.assertEqual(status, 0, "isolated acceptance failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    firewall = parser.add_mutually_exclusive_group()
    firewall.add_argument("--simulate-fw3", action="store_true")
    firewall.add_argument("--simulate-fw4", action="store_true")
    parser.add_argument("--subscription-file")
    parser.add_argument("--dnsmasq-binary", help="Enable real dnsmasq lifecycle acceptance")
    parser.add_argument('--external-system-dns', action='store_true', help='Verify IPv4/IPv6 system resolvers cannot bypass protected DNS')
    options = parser.parse_args()
    BINARY = options.binary
    SIMULATE_FW3 = options.simulate_fw3
    SIMULATE_FW4 = options.simulate_fw4
    DNSMASQ_BINARY = str(Path(options.dnsmasq_binary).resolve()) if options.dnsmasq_binary else None
    EXTERNAL_SYSTEM_DNS = options.external_system_dns
    PRIVATE_SUBSCRIPTION = Path(options.subscription_file).read_text() if options.subscription_file else None
    # The decorator was evaluated before parsing the CLI argument.
    RuntimeAcceptance.__unittest_skip__ = False
    unittest.main(argv=[sys.argv[0]], verbosity=2)
