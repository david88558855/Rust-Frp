#!/usr/bin/env python3
"""End to end check for Rust-Frp.

Runs the freshly built `rust-frp` binary as frps and frpc, points it at local
echo services, and verifies real traffic through the tunnel. Only the standard
library is used so this can run unchanged on Linux, macOS and Windows.

Usage:
    python3 tests/e2e/e2e.py [path/to/rust-frp]

This exists because unit tests cannot catch a peer protocol mismatch. The
visitor signature check, for instance, compiled, passed every unit test, and
still rejected every visitor connection, because the unit test and the
implementation shared the same wrong assumption. Only running the two binaries
against each other found it.
"""

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Config files are written here rather than next to the script so a local run
# does not dirty the working tree.
WORK = tempfile.mkdtemp(prefix="rust-frp-e2e-")

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail else ""))
    sys.stdout.flush()


# --------------------------------------------------------------- echo services


def tcp_echo(port, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.3)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_tcp_session, args=(conn,), daemon=True).start()
    srv.close()


def _tcp_session(conn):
    with conn:
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            conn.sendall(b"echo:" + data)


def udp_echo(port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.3)
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        sock.sendto(b"echo:" + data, peer)
    sock.close()


def http_echo(port, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.3)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_http_session, args=(conn,), daemon=True).start()
    srv.close()


def _http_session(conn):
    with conn:
        conn.settimeout(2.0)
        try:
            request = conn.recv(4096)
        except OSError:
            return
        if not request:
            return
        host = ""
        for line in request.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode()
        body = ("backend saw host=" + host).encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )


# ------------------------------------------------------------------- processes


class Node:
    """One `rust-frp frps|frpc` process."""

    def __init__(self, binary, role, name, config):
        self.path = os.path.join(WORK, name + ".toml")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(config)
        self.binary = binary
        self.role = role
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            [self.binary, self.role, "-c", self.path],
            cwd=WORK,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def wait_for_port(port, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def tcp_roundtrip(port, payload=b"hello"):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(payload)
            sock.settimeout(10)
            data = sock.recv(4096)
    except OSError as exc:
        return False, "socket error: %s" % exc
    if data == b"echo:" + payload:
        return True, data.decode(errors="replace")
    return False, "unexpected reply %r" % (data,)


def udp_roundtrip(port, payload=b"hello-udp"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return False, "socket error: %s" % exc
    finally:
        sock.close()
    if data == b"echo:" + payload:
        return True, data.decode(errors="replace")
    return False, "unexpected reply %r" % (data,)


def http_roundtrip(port, host):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(
                ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode()
            )
            sock.settimeout(10)
            chunks = []
            while True:
                try:
                    part = sock.recv(4096)
                except OSError:
                    break
                if not part:
                    break
                chunks.append(part)
    except OSError as exc:
        return False, "socket error: %s" % exc
    raw = b"".join(chunks)
    if b"200 OK" in raw and ("backend saw host=" + host).encode() in raw:
        return True, raw.split(b"\r\n\r\n")[-1].decode(errors="replace")
    return False, raw[:160].decode(errors="replace")


# ------------------------------------------------------------------ scenarios


def scenario_default(binary):
    print("== scenario: default transport (tcpMux, tcp + udp + http vhost) ==")
    frps = Node(
        binary,
        "frps",
        "e2e-frps",
        """bindAddr = "127.0.0.1"
bindPort = 19000
vhostHTTPPort = 19200
allowPorts = [{ start = 19100, end = 19110 }]

[auth]
method = "token"
token = "e2e-token"
""",
    ).start()
    if not wait_for_port(19000):
        check("default: frps listens", False)
        frps.stop()
        return

    frpc = Node(
        binary,
        "frpc",
        "e2e-frpc",
        """serverAddr = "127.0.0.1"
serverPort = 19000

[auth]
method = "token"
token = "e2e-token"

[[proxies]]
name = "tcp-echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = 19001
remotePort = 19100

[[proxies]]
name = "udp-echo"
type = "udp"
localIP = "127.0.0.1"
localPort = 19002
remotePort = 19101

[[proxies]]
name = "web"
type = "http"
localIP = "127.0.0.1"
localPort = 19003
customDomains = ["web.test"]
""",
    ).start()

    if not wait_for_port(19100):
        check("default: proxy registered", False)
    else:
        check("default: proxy registered", True)
        ok, detail = tcp_roundtrip(19100, b"first")
        check("default: tcp forwarding", ok, detail)
        ok, detail = tcp_roundtrip(19100, b"second")
        check("default: a second work connection", ok, detail)
        ok, detail = udp_roundtrip(19101)
        check("default: udp forwarding", ok, detail)
        ok, detail = http_roundtrip(19200, "web.test")
        check("default: http vhost routing", ok, detail)

    frpc.stop()
    frps.stop()


def scenario_no_mux(binary):
    print("== scenario: transport.tcpMux = false on both peers ==")
    frps = Node(
        binary,
        "frps",
        "e2e-frps2",
        """bindAddr = "127.0.0.1"
bindPort = 19010
allowPorts = [{ start = 19110, end = 19110 }]

[auth]
method = "token"
token = "t"

[transport]
tcpMux = false
""",
    ).start()
    if not wait_for_port(19010):
        check("no-tcpmux: frps listens", False)
        frps.stop()
        return
    frpc = Node(
        binary,
        "frpc",
        "e2e-frpc2",
        """serverAddr = "127.0.0.1"
serverPort = 19010

[auth]
method = "token"
token = "t"

[transport]
tcpMux = false

[[proxies]]
name = "tcp"
type = "tcp"
localPort = 19001
remotePort = 19110
""",
    ).start()
    if not wait_for_port(19110):
        check("no-tcpmux: proxy registered", False)
    else:
        check("no-tcpmux: proxy registered", True)
        ok, detail = tcp_roundtrip(19110, b"no-mux")
        check("no-tcpmux: tcp forwarding", ok, detail)
    frpc.stop()
    frps.stop()


def scenario_tls(binary):
    print("== scenario: transport.tls.enable = true ==")
    frps = Node(
        binary,
        "frps",
        "e2e-frps3",
        """bindAddr = "127.0.0.1"
bindPort = 19020
allowPorts = [{ start = 19120, end = 19120 }]

[auth]
method = "token"
token = "t"
""",
    ).start()
    if not wait_for_port(19020):
        check("tls: frps listens", False)
        frps.stop()
        return
    frpc = Node(
        binary,
        "frpc",
        "e2e-frpc3",
        """serverAddr = "127.0.0.1"
serverPort = 19020

[auth]
method = "token"
token = "t"

[transport.tls]
enable = true

[[proxies]]
name = "tcp"
type = "tcp"
localPort = 19001
remotePort = 19120
""",
    ).start()
    if not wait_for_port(19120):
        check("tls: proxy registered", False)
    else:
        check("tls: proxy registered", True)
        ok, detail = tcp_roundtrip(19120, b"over-tls")
        check("tls: tcp forwarding", ok, detail)
    frpc.stop()
    frps.stop()


def scenario_stcp_visitor(binary):
    print("== scenario: stcp proxy + stcp visitor across two frpc instances ==")
    frps = Node(
        binary,
        "frps",
        "e2e-frps4",
        """bindAddr = "127.0.0.1"
bindPort = 19030

[auth]
method = "token"
token = "t"
""",
    ).start()
    if not wait_for_port(19030):
        check("stcp: frps listens", False)
        frps.stop()
        return

    provider = Node(
        binary,
        "frpc",
        "e2e-frpc4a",
        """serverAddr = "127.0.0.1"
serverPort = 19030

[auth]
method = "token"
token = "t"

[[proxies]]
name = "secret"
type = "stcp"
localPort = 19001
secretKey = "shared-secret"
""",
    ).start()
    time.sleep(2.0)

    visitor = Node(
        binary,
        "frpc",
        "e2e-frpc4b",
        """serverAddr = "127.0.0.1"
serverPort = 19030

[auth]
method = "token"
token = "t"

[[visitors]]
name = "secret-visitor"
type = "stcp"
serverName = "secret"
secretKey = "shared-secret"
bindPort = 19300
""",
    ).start()

    if not wait_for_port(19300):
        check("stcp: visitor bound its local port", False)
    else:
        check("stcp: visitor bound its local port", True)
        ok, detail = tcp_roundtrip(19300, b"through-visitor")
        check("stcp: traffic reaches the provider's local service", ok, detail)
        ok, detail = tcp_roundtrip(19300, b"second-visitor-conn")
        check("stcp: a second visitor connection", ok, detail)

    visitor.stop()
    provider.stop()
    frps.stop()


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(HERE)), "target", "release", "rust-frp"
    )
    if not os.path.exists(binary):
        print("missing binary at " + binary)
        return 1
    print("using " + binary)

    out = subprocess.run([binary, "info"], capture_output=True, text=True)
    check("rust-frp info", out.returncode == 0)

    stop = threading.Event()
    for target, args in (
        (tcp_echo, (19001, stop)),
        (udp_echo, (19002, stop)),
        (http_echo, (19003, stop)),
    ):
        threading.Thread(target=target, args=args, daemon=True).start()
    time.sleep(0.4)

    try:
        scenario_default(binary)
        scenario_no_mux(binary)
        scenario_tls(binary)
        scenario_stcp_visitor(binary)
    finally:
        stop.set()

    failed = [r for r in results if not r[1]]
    print("")
    print("%d/%d checks passed" % (len(results) - len(failed), len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
