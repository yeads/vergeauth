#!/usr/bin/env python3
"""Wire-level integration tests; all traffic stays on loopback."""

import base64
import concurrent.futures
import contextlib
import os
from pathlib import Path
import queue
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve())


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError(f"expected {length} bytes, received {bytes(data)!r}")
        data.extend(part)
    return bytes(data)


def recv_headers(sock):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        data.extend(recv_exact(sock, 1))
        if len(data) > 100000:
            raise ValueError("oversized test response")
    return bytes(data)


def recv_all(sock):
    result = bytearray()
    while True:
        data = sock.recv(65536)
        if not data:
            return bytes(result)
        result.extend(data)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def auth(user="alice", password="secret"):
    return b"Proxy-Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()) + b"\r\n"


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            head = recv_headers(self.request)
            line, *fields = head.split(b"\r\n")
            method, target, _ = line.split(b" ", 2)
            headers = {}
            for field in fields:
                if field:
                    key, value = field.split(b":", 1)
                    headers[key.lower()] = value.strip()
            self.server.requests.put((line, headers))
            if method == b"CONNECT":
                if target.startswith(b"deny."):
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                if target.startswith(b"invalid."):
                    self.request.sendall(b"this is not HTTP\r\n\r\n")
                    return
                if target.startswith(b"interim."):
                    self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if target.startswith(b"greet."):
                    self.request.sendall(b"greeting")
                if target.startswith(b"halfclose."):
                    data = recv_all(self.request)
                    self.request.sendall(b"after-fin:" + data)
                    return
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        return
                    self.request.sendall(data)
            else:
                if headers.get(b"expect", b"").lower() == b"100-continue":
                    self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                body = bytearray()
                if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                    while True:
                        size = bytearray()
                        while not size.endswith(b"\r\n"):
                            size.extend(recv_exact(self.request, 1))
                        length = int(size.strip().split(b";")[0], 16)
                        if not length:
                            assert recv_exact(self.request, 2) == b"\r\n"
                            break
                        body.extend(recv_exact(self.request, length))
                        assert recv_exact(self.request, 2) == b"\r\n"
                else:
                    body.extend(recv_exact(self.request, int(headers.get(b"content-length", b"0"))))
                self.server.bodies.put(bytes(body))
                if target.endswith(b"/chunked"):
                    self.request.sendall(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n"
                        b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-End: done\r\n\r\n")
                elif target.endswith(b"/eof"):
                    self.request.sendall(b"HTTP/1.0 200 OK\r\n\r\neof-body")
                elif target.endswith(b"/empty"):
                    self.request.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                elif target.endswith(b"/early"):
                    self.request.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                                         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                elif target.endswith(b"/malformed"):
                    self.request.sendall(b"broken\r\n\r\n")
                else:
                    response = bytes(body) if method == b"POST" else b"upstream-ok"
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                                         str(len(response)).encode() + b"\r\nConnection: keep-alive\r\n\r\n")
                    if method != b"HEAD":
                        self.request.sendall(response)
                    # Do not close until vergeauth closes: exercises response framing.
                    self.request.recv(1)
        except (OSError, EOFError):
            pass
        except Exception as exc:
            self.server.errors.put(exc)


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
        self.requests = queue.Queue()
        self.bodies = queue.Queue()
        self.errors = queue.Queue()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()


class Proxy:
    def __init__(self, upstream, text=None, daemon=False, default=False):
        self.directory = tempfile.TemporaryDirectory(prefix="vergeauth-test-")
        self.path = Path(self.directory.name) / ".vergeauth"
        self.port = unused_port()
        self.upstream_port = upstream.server_address[1]
        self.path.write_text(text or self.config())
        self.log = open(Path(self.directory.name) / "stderr.log", "w+")
        self.env = os.environ.copy()
        self.env["HOME"] = self.directory.name
        args = [BINARY] + ([] if default else ["-f", str(self.path)])
        if daemon:
            args.append("-d")
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log, env=self.env)
        self.daemon = daemon
        self.pid = None
        try:
            if daemon:
                if self.process.wait(timeout=5) != 0:
                    raise RuntimeError(self.logs())
                self.pid = int(Path(str(self.path) + ".pid").read_text())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not daemon and self.process.poll() is not None:
                    raise RuntimeError(self.logs())
                try:
                    with self.connect():
                        break
                except OSError:
                    time.sleep(0.01)
            else:
                raise TimeoutError(self.logs())
        except Exception:
            self.close()
            raise

    def config(self, users="user alice secret\nuser bob 'space password'\n", endpoint=None):
        return f"listen {self.port}\nupstream {endpoint or f'127.0.0.1:{self.upstream_port}'}\n{users}"

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=4)

    def logs(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def reload(self, text):
        self.path.write_text(text)
        result = subprocess.run([BINARY, "-r", "-f", str(self.path)], capture_output=True, timeout=5)
        if result.returncode:
            raise AssertionError(result.stderr.decode())

    def close(self):
        if self.daemon and self.pid:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not Path(str(self.path) + ".pid").read_text().strip():
                    break
                time.sleep(0.01)
        elif self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        code = self.process.returncode
        logs = self.logs()
        self.log.close()
        self.directory.cleanup()
        if code not in (None, 0):
            raise AssertionError(f"proxy exited with {code}: {logs}")
        if "ERROR: AddressSanitizer" in logs or "runtime error:" in logs:
            raise AssertionError(logs)


class Integration(unittest.TestCase):
    def setUp(self):
        self.upstream = Upstream()
        self.proxy = Proxy(self.upstream)

    def tearDown(self):
        try:
            self.proxy.close()
        finally:
            self.upstream.close()
        if not self.upstream.errors.empty():
            raise self.upstream.errors.get()

    def request(self, target=b"http://example.test/", credentials=auth(), extra=b"", method=b"GET", body=b""):
        with self.proxy.connect() as sock:
            sock.sendall(method + b" " + target + b" HTTP/1.1\r\nHost: example.test\r\n" +
                         credentials + extra + b"\r\n" + body)
            return recv_all(sock)

    def socks(self, user=b"alice", password=b"secret"):
        sock = self.proxy.connect()
        self.addCleanup(sock.close)
        sock.sendall(b"\x05\x02\x00\x02")
        self.assertEqual(recv_exact(sock, 2), b"\x05\x02")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        self.assertEqual(recv_exact(sock, 2), b"\x01\x00")
        return sock

    def socks_connect(self, host=b"example.test", payload=b""):
        sock = self.socks()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb" + payload)
        self.assertEqual(recv_exact(sock, 10)[:2], b"\x05\x00")
        return sock

    def test_http_authentication_and_header_filtering(self):
        for credentials in (b"", auth(password="wrong"), b"Proxy-Authorization: Bearer abc\r\n",
                            b"Proxy-Authorization: Basic YTpi=\r\n", auth() + auth()):
            response = self.request(credentials=credentials)
            self.assertTrue(response.startswith(b"HTTP/1.1 407 "), response)
            self.assertIn(b"Proxy-Authenticate: Basic", response)
        self.assertTrue(self.upstream.requests.empty())
        response = self.request(extra=b"Proxy-Connection: keep-alive\r\nConnection: X-Private\r\nX-Private: hidden\r\nAuthorization: Bearer origin-token\r\n")
        self.assertTrue(response.endswith(b"upstream-ok"), response)
        self.assertIn(b"Connection: close\r\n", response)
        line, headers = self.upstream.requests.get(timeout=2)
        self.assertEqual(line, b"GET http://example.test/ HTTP/1.1")
        self.assertNotIn(b"proxy-authorization", headers)
        self.assertNotIn(b"proxy-connection", headers)
        self.assertNotIn(b"x-private", headers)
        self.assertEqual(headers[b"authorization"], b"Bearer origin-token")
        self.assertEqual(headers[b"connection"], b"close")
        self.assertTrue(self.request(credentials=auth("bob", "space password")).endswith(b"upstream-ok"))

    def test_fragmented_http_and_no_authentication_bypass_by_pipeline(self):
        request = b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n" + auth() + b"\r\n"
        with self.proxy.connect() as sock:
            for part in request:
                sock.sendall(bytes([part]))
            self.assertTrue(recv_all(sock).endswith(b"upstream-ok"))
        self.upstream.requests.get(timeout=2)
        with self.proxy.connect() as sock:
            sock.sendall(request + b"GET http://forbidden.test/ HTTP/1.1\r\nHost: forbidden.test\r\n\r\n")
            self.assertTrue(recv_all(sock).endswith(b"upstream-ok"))
        self.assertIn(b"example.test", self.upstream.requests.get(timeout=2)[0])
        self.assertTrue(self.upstream.requests.empty())

    def test_post_content_length_and_expect_continue(self):
        body = bytes(range(256)) * 4096
        response = self.request(method=b"POST", extra=f"Content-Length: {len(body)}\r\n".encode(), body=body)
        self.assertEqual(response.split(b"\r\n\r\n", 1)[1], body)
        self.assertEqual(self.upstream.bodies.get(timeout=2), body)
        with self.proxy.connect() as sock:
            sock.sendall(b"POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\n" + auth() +
                         b"Content-Length: 4\r\nExpect: 100-continue\r\n\r\n")
            self.assertTrue(recv_headers(sock).startswith(b"HTTP/1.1 100 "))
            sock.sendall(b"data")
            self.assertTrue(recv_all(sock).endswith(b"data"))

    def test_chunked_body_and_response(self):
        response = self.request(method=b"POST", extra=b"Transfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n",
                                body=b"3;ext=yes\r\nabc\r\n2\r\nde\r\n0\r\nProxy-Authorization: hidden\r\n\r\n")
        self.assertTrue(response.endswith(b"abcde"), response)
        self.assertEqual(self.upstream.bodies.get(timeout=2), b"abcde")
        _, headers = self.upstream.requests.get(timeout=2)
        self.assertNotIn(b"trailer", headers)
        response = self.request(target=b"http://example.test/chunked")
        self.assertIn(b"Transfer-Encoding: chunked", response)
        self.assertNotIn(b"X-End", response)
        encoded = response.split(b"\r\n\r\n", 1)[1]
        decoded = bytearray()
        while True:
            size, encoded = encoded.split(b"\r\n", 1)
            length = int(size, 16)
            if not length:
                self.assertEqual(encoded, b"\r\n")
                break
            decoded.extend(encoded[:length])
            self.assertEqual(encoded[length:length + 2], b"\r\n")
            encoded = encoded[length + 2:]
        self.assertEqual(decoded, b"hello world")

    def test_http_response_framing(self):
        self.assertTrue(self.request(target=b"http://example.test/eof").endswith(b"eof-body"))
        self.assertTrue(self.request(target=b"http://example.test/empty").startswith(b"HTTP/1.1 204 "))
        response = self.request(method=b"HEAD")
        self.assertEqual(response.split(b"\r\n\r\n", 1)[1], b"")
        response = self.request(target=b"http://example.test/early")
        self.assertIn(b"HTTP/1.1 103 ", response)
        self.assertIn(b"HTTP/1.1 200 ", response)
        self.assertTrue(response.endswith(b"ok"))
        self.assertTrue(self.request(target=b"http://example.test/malformed").startswith(b"HTTP/1.1 502 "))

    def test_invalid_http_and_limits(self):
        invalid = [
            b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            b"Content-Length: 2\r\nContent-Length: 3\r\n",
            b"Host: duplicate.test\r\n",
            b"Connection: Content-Length\r\nContent-Length: 0\r\n",
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n",
        ]
        for extra in invalid:
            self.assertTrue(self.request(extra=extra).startswith(b"HTTP/1.1 400 "))
        self.assertTrue(self.request(target=b"http://user@host/").startswith(b"HTTP/1.1 400 "))
        self.assertTrue(self.request(target=b"https://example.test/").startswith(b"HTTP/1.1 400 "))
        with self.proxy.connect() as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nX-Large: " + b"a" * 66000)
            self.assertTrue(recv_all(sock).startswith(b"HTTP/1.1 431 "))
        self.assertTrue(self.upstream.requests.empty())

    def test_connect_http_pipelined_data_and_half_close(self):
        with self.proxy.connect() as sock:
            sock.sendall(b"CONNECT greet.test:443 HTTP/1.1\r\nHost: greet.test:443\r\n" + auth() + b"\r\nfirst")
            self.assertEqual(recv_headers(sock), b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.assertEqual(recv_exact(sock, 13), b"greetingfirst")
            sock.sendall(b"second")
            self.assertEqual(recv_exact(sock, 6), b"second")
        line, headers = self.upstream.requests.get(timeout=2)
        self.assertEqual(line, b"CONNECT greet.test:443 HTTP/1.1")
        self.assertNotIn(b"proxy-authorization", headers)
        with self.proxy.connect() as sock:
            sock.sendall(b"CONNECT halfclose.test:443 HTTP/1.1\r\nHost: halfclose.test:443\r\n" + auth() + b"\r\n")
            recv_headers(sock)
            sock.sendall(b"last-data")
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_all(sock), b"after-fin:last-data")

    def test_rejected_http_drains_late_input(self):
        with self.proxy.connect() as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nX-Large: " + b"a" * 66000)
            response = recv_headers(sock)
            self.assertTrue(response.startswith(b"HTTP/1.1 431 "), response)
            self.assertIn(b"Content-Length: 0\r\n", response)
            self.assertIn(b"Connection: close\r\n", response)
            # The peer may still be sending when it receives the error response.
            sock.sendall(b"b" * (1024 * 1024))
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_all(sock), b"")
        self.assertTrue(self.upstream.requests.empty())

    def test_socks_authentication_errors(self):
        with self.proxy.connect() as sock:
            sock.sendall(b"\x05\x01\x00")
            self.assertEqual(recv_all(sock), b"\x05\xff")
        for credentials in (b"\x01\x05alice\x03bad", b"\x02\x01a", b"\x01\x00"):
            with self.proxy.connect() as sock:
                sock.sendall(b"\x05\x01\x02")
                self.assertEqual(recv_exact(sock, 2), b"\x05\x02")
                sock.sendall(credentials)
                self.assertEqual(recv_all(sock), b"\x01\x01")
        self.assertTrue(self.upstream.requests.empty())

    def test_socks_addresses_and_fragmented_pipeline(self):
        addresses = [
            (b"\x01\x7f\x00\x00\x01", b"127.0.0.1:443"),
            (b"\x04" + socket.inet_pton(socket.AF_INET6, "::1"), b"[::1]:443"),
            (b"\x03" + bytes([len(b"example.test")]) + b"example.test", b"example.test:443"),
        ]
        for address, target in addresses:
            with self.proxy.connect() as sock:
                packet = b"\x05\x01\x02\x01\x05alice\x06secret\x05\x01\x00" + address + b"\x01\xbbping"
                for byte in packet:
                    sock.sendall(bytes([byte]))
                self.assertEqual(recv_exact(sock, 4), b"\x05\x02\x01\x00")
                self.assertEqual(recv_exact(sock, 10)[:2], b"\x05\x00")
                self.assertEqual(recv_exact(sock, 4), b"ping")
            line, headers = self.upstream.requests.get(timeout=2)
            self.assertEqual(line, b"CONNECT " + target + b" HTTP/1.1")
            self.assertNotIn(b"proxy-authorization", headers)

    def test_socks_invalid_commands_and_destinations(self):
        for packet, code in [
            (b"\x05\x02\x00\x01", 7),
            (b"\x05\x03\x00\x01", 7),
            (b"\x05\x01\x00\x09", 8),
            (b"\x05\x01\x01\x01", 1),
            (b"\x05\x01\x00\x03\x03a\r\n\x01\xbb", 8),
            (b"\x05\x01\x00\x03\x03a\x00b\x01\xbb", 8),
        ]:
            sock = self.socks()
            sock.sendall(packet)
            self.assertEqual(recv_all(sock)[:2], bytes([5, code]))
        self.assertTrue(self.upstream.requests.empty())

    def test_upstream_connect_failure_and_interim(self):
        for name in (b"deny.test", b"invalid.test"):
            sock = self.socks()
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + b"\x01\xbb")
            self.assertNotEqual(recv_all(sock)[1], 0)
            response = self.request(target=name + b":443", method=b"CONNECT")
            self.assertTrue(response.startswith(b"HTTP/1.1 502 "), response)
        sock = self.socks_connect(b"interim.test", b"data")
        self.assertEqual(recv_exact(sock, 4), b"data")

    def test_backpressure_and_concurrency(self):
        payload = os.urandom(2 * 1024 * 1024)
        sock = self.socks_connect()
        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
            sending = pool.submit(sock.sendall, payload)
            time.sleep(0.05)
            self.assertEqual(recv_exact(sock, len(payload)), payload)
            sending.result(timeout=5)
            futures = [pool.submit(self.request) for _ in range(24)]
            for future in futures:
                self.assertTrue(future.result(timeout=5).endswith(b"upstream-ok"))
        tasks = Path(f"/proc/{self.proxy.process.pid}/task")
        if tasks.is_dir():
            self.assertEqual(len(list(tasks.iterdir())), 1)

    def test_reload_only_users_and_preserve_existing_tunnel(self):
        sock = self.socks_connect()
        self.proxy.reload("listen invalid\nupstream invalid\nuser alice changed\n")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.request(credentials=auth(password="changed")).startswith(b"HTTP/1.1 200 "):
                break
            time.sleep(0.01)
        else:
            self.fail(self.proxy.logs())
        self.assertTrue(self.request().startswith(b"HTTP/1.1 407 "))
        sock.sendall(b"still-connected")
        self.assertEqual(recv_exact(sock, 15), b"still-connected")
        self.proxy.reload("user alice broken\nuser alice duplicate\n")
        deadline = time.monotonic() + 3
        while "reload rejected" not in self.proxy.logs() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn("reload rejected", self.proxy.logs())
        self.assertTrue(self.request(credentials=auth(password="changed")).startswith(b"HTTP/1.1 200 "))
        self.proxy.reload("# no users\n")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.request(credentials=auth(password="changed")).startswith(b"HTTP/1.1 407 "):
                break
            time.sleep(0.01)
        else:
            self.fail("empty user table was not loaded")
        sock.sendall(b"ok")
        self.assertEqual(recv_exact(sock, 2), b"ok")

    def test_default_path_daemon_and_pid_lock(self):
        second = Proxy(self.upstream, daemon=True, default=True)
        try:
            result = subprocess.run([BINARY, "-d"], env=second.env, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            second.reload(second.config(users="user alice changed\n"))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with second.connect() as sock:
                    sock.sendall(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n" + auth(password="changed") + b"\r\n")
                    if recv_all(sock).startswith(b"HTTP/1.1 200 "):
                        break
                time.sleep(0.01)
            else:
                self.fail("daemon did not load new users")
        finally:
            second.close()
        result = subprocess.run([BINARY, "-f", str(self.proxy.path)], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.request().endswith(b"upstream-ok"))

    def test_configuration_validation_and_stale_pid(self):
        with tempfile.TemporaryDirectory(prefix="vergeauth-config-") as directory:
            path = Path(directory) / "config"
            for text in ("", "listen 0\nupstream localhost:1\n", "listen 12\nupstream bad\n",
                         "listen 12\nlisten 13\nupstream localhost:1\n", "unknown value\n",
                         "listen 12\nupstream localhost:1\nuser alice 'unterminated\n",
                         "listen 12\nupstream localhost:1\nuser alice a\nuser alice b\n"):
                path.write_text(text)
                result = subprocess.run([BINARY, "-f", str(path)], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, text)
            path.write_text(self.proxy.config())
            Path(str(path) + ".pid").write_text(f"{os.getpid()}\n")
            result = subprocess.run([BINARY, "-r", "-f", str(path)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            # An occupied listen port is also reported to the daemon's parent.
            result = subprocess.run([BINARY, "-d", "-f", str(path)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_unreachable_upstream(self):
        # Start with a valid listener and an unused upstream endpoint.
        with tempfile.TemporaryDirectory(prefix="vergeauth-unreachable-") as directory:
            path = Path(directory) / "config"
            port, upstream_port = unused_port(), unused_port()
            path.write_text(f"listen {port}\nupstream 127.0.0.1:{upstream_port}\nuser alice secret\n")
            process = subprocess.Popen([BINARY, "-f", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.01)
                with sock:
                    sock.sendall(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n" + auth() + b"\r\n")
                    self.assertTrue(recv_all(sock).startswith(b"HTTP/1.1 502 "))
            finally:
                process.terminate()
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)


if __name__ == "__main__":
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
    except PermissionError as exc:
        print(f"SKIP: local TCP sockets are prohibited: {exc}")
        sys.exit(77)
    unittest.main(verbosity=2)
