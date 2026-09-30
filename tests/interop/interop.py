#!/usr/bin/env python3
"""Wire compatibility check against upstream frp.

Runs every combination of a Rust peer and an upstream frp release, one as the
server and one as the client, and verifies real traffic through the tunnel.

Usage:
    python3 tests/interop/interop.py \
        --rust target/release/rust-frp \
        --upstream /path/to/frp_0.71.0_linux_amd64

`--upstream` is a directory containing `frps`/`frpc` (`.exe` on Windows) from a
frp release whose version matches the one this implementation targets.

Why this is separate from `tests/e2e/e2e.py`: the e2e suite proves the Rust
peers work together, which cannot detect a protocol detail both sides get
wrong the same way. A wrong-but-self-consistent key derivation, for instance,
passed the whole unit suite and the whole e2e suite while matching neither frpc
nor frps.
"""

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = tempfile.mkdtemp(prefix="frp-interop-")

TOKEN = "interop-token"
LOCAL_TCP = 19001
LOCAL_UDP = 19002
LOCAL_HTTP = 19003

results = []


def check(label, name, ok, detail=""):
    results.append((label, name, ok))
    print(
        "  %-4s %s%s"
        % ("PASS" if ok else "FAIL", name, (" :: " + detail) if detail else "")
    )
    sys.stdout.flush()


# ------------------------------------------------------------------ echo services


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


# ---------------------------------------------------------------------- processes


class Node:
    def __init__(self, binary, role, config, label):
        self.path = os.path.join(WORK, "%s-%s.toml" % (label, role))
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(config)
        self.log = os.path.join(WORK, "%s-%s.log" % (label, role))
        self.handle = open(self.log, "wb")
        self.binary = binary
        self.role = role
        self.proc = None

    def start(self):
        # `rust-frp` is one binary with frps/frpc subcommands; an upstream
        # release is two binaries that take the config directly.
        if "rust-frp" in os.path.basename(self.binary).lower():
            args = [self.binary, self.role, "-c", self.path]
        else:
            args = [self.binary, "-c", self.path]
        self.proc = subprocess.Popen(
            args, cwd=WORK, stdout=self.handle, stderr=subprocess.STDOUT
        )
        return self

    def tail(self, lines=25):
        try:
            self.handle.flush()
        except ValueError:
            pass
        try:
            with open(self.log, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(text[-lines:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        try:
            self.handle.close()
        except ValueError:
            pass


def wait_for_port(port, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# -------------------------------------------------------------------- round trips


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
    return False, raw[:200].decode(errors="replace")


# --------------------------------------------------------------------- scenarios


def find_binary(directory, name):
    for candidate in (name, name + ".exe"):
        path = os.path.join(directory, candidate)
        if os.path.exists(path):
            return path
    return None


def run_pair(frps_exe, frpc_exe, label, base):
    ctrl = base
    remote_tcp = base + 1
    remote_udp = base + 2
    vhost = base + 3

    print("")
    print("== %s ==" % label)
    print("   frps %s" % frps_exe)
    print("   frpc %s" % frpc_exe)

    frps = Node(
        frps_exe,
        "frps",
        """bindAddr = "127.0.0.1"
bindPort = %d
vhostHTTPPort = %d
allowPorts = [{ start = %d, end = %d }]

[auth]
method = "token"
token = "%s"
"""
        % (ctrl, vhost, remote_tcp, remote_udp, TOKEN),
        label,
    ).start()

    if not wait_for_port(ctrl):
        check(label, "server listening", False, frps.tail(15))
        frps.stop()
        return

    frpc = Node(
        frpc_exe,
        "frpc",
        """serverAddr = "127.0.0.1"
serverPort = %d

[auth]
method = "token"
token = "%s"

[[proxies]]
name = "tcp-echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d

[[proxies]]
name = "udp-echo"
type = "udp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d

[[proxies]]
name = "web"
type = "http"
localIP = "127.0.0.1"
localPort = %d
customDomains = ["web.test"]
"""
        % (ctrl, TOKEN, LOCAL_TCP, remote_tcp, LOCAL_UDP, remote_udp, LOCAL_HTTP),
        label,
    ).start()

    if not wait_for_port(remote_tcp, timeout=25):
        check(label, "proxy registered", False)
        print("   --- frpc log ---")
        print("   " + frpc.tail(20).replace("\n", "\n   "))
        print("   --- frps log ---")
        print("   " + frps.tail(20).replace("\n", "\n   "))
        frpc.stop()
        frps.stop()
        return

    check(label, "proxy registered", True)

    ok, detail = tcp_roundtrip(remote_tcp, b"interop")
    check(label, "tcp forwarding", ok, detail)
    if ok:
        ok2, detail2 = tcp_roundtrip(remote_tcp, b"second")
        check(label, "second tcp connection", ok2, detail2)

    ok, detail = udp_roundtrip(remote_udp)
    check(label, "udp forwarding", ok, detail)

    ok, detail = http_roundtrip(vhost, "web.test")
    check(label, "http vhost routing", ok, detail)

    frpc.stop()
    frps.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, help="path to the rust-frp binary")
    parser.add_argument("--upstream", required=True, help="frp release directory")
    parser.add_argument(
        "--only",
        default="all",
        help="comma separated subset of rust-frps+frpc,frps+rust-frpc,rust-frps+rust-frpc,frps+frpc",
    )
    args = parser.parse_args()

    rust = os.path.abspath(args.rust)
    if not os.path.exists(rust):
        print("missing rust binary at " + rust)
        return 1
    up_frps = find_binary(args.upstream, "frps")
    up_frpc = find_binary(args.upstream, "frpc")
    if not up_frps or not up_frpc:
        print("no frps/frpc in " + args.upstream)
        return 1

    upstream_version = subprocess.run(
        [up_frps, "--version"], capture_output=True, text=True
    ).stdout.strip()
    rust_version = subprocess.run(
        [rust, "info"], capture_output=True, text=True
    ).stdout.splitlines()[0]
    print("rust     : %s" % rust_version)
    print("upstream : %s" % upstream_version)
    if "0.71.0" not in upstream_version:
        print("WARNING: upstream is not v0.71.0; results may not be meaningful")

    stop = threading.Event()
    for target, port in ((tcp_echo, LOCAL_TCP), (udp_echo, LOCAL_UDP), (http_echo, LOCAL_HTTP)):
        threading.Thread(target=target, args=(port, stop), daemon=True).start()
    time.sleep(0.4)

    combos = [
        ("rust-frps+frpc", rust, up_frpc, 31000),
        ("frps+rust-frpc", up_frps, rust, 31100),
        ("rust-frps+rust-frpc", rust, rust, 31200),
        ("frps+frpc", up_frps, up_frpc, 31300),
    ]
    wanted = args.only.split(",")
    try:
        for label, frps_exe, frpc_exe, base in combos:
            if args.only != "all" and label not in wanted:
                continue
            run_pair(frps_exe, frpc_exe, label, base)
    finally:
        stop.set()

    print("")
    print("=== summary ===")
    labels = []
    for label, _, _ in results:
        if label not in labels:
            labels.append(label)
    overall = 0
    total = 0
    for label in labels:
        rows = [r for r in results if r[0] == label]
        passed = sum(1 for r in rows if r[2])
        overall += passed
        total += len(rows)
        print("  %-22s %d/%d" % (label, passed, len(rows)))
    print("  %-22s %d/%d" % ("total", overall, total))

    failed = [r for r in results if not r[2]]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
