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
LOCAL_SECURE = 19004

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


def safe_name(label):
    """Labels are human readable; filenames must not contain spaces or `>`."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in label)


class Node:
    def __init__(self, binary, role, config, label):
        stem = safe_name(label)
        self.path = os.path.join(WORK, "%s-%s.toml" % (stem, role))
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(config)
        self.log = os.path.join(WORK, "%s-%s.log" % (stem, role))
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
    """Sends a payload and reads exactly what the echo service sends back."""
    expected = b"echo:" + payload
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
            sock.sendall(payload)
            sock.settimeout(15)
            data = b""
            while len(data) < len(expected):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        return False, "socket error: %s" % exc
    if data == expected:
        return True, "%d bytes echoed" % len(payload) if len(payload) > 64 else data.decode(
            errors="replace"
        )
    return False, "got %d of %d bytes" % (len(data), len(expected))


def tcp_bulk_roundtrip(port, size):
    """Sends `size` bytes and checks every byte comes back."""
    payload = b"A" * size
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
            sock.sendall(payload)
            sock.settimeout(2)
            data = b""
            deadline = time.time() + 25
            while time.time() < deadline:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    if data.replace(b"echo:", b"") == payload:
                        break
                    continue
                if not chunk:
                    break
                data += chunk
                if data.replace(b"echo:", b"") == payload:
                    break
    except OSError as exc:
        return False, "socket error: %s" % exc
    rebuilt = data.replace(b"echo:", b"")
    if rebuilt == payload:
        return True, "%d bytes round tripped" % size
    return False, "rebuilt %d of %d bytes" % (len(rebuilt), size)

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


def run_pair(frps_exe, frpc_exe, label, base, client_extra=""):
    ctrl = base
    remote_tcp = base + 1
    remote_udp = base + 2
    vhost = base + 3
    remote_secure = base + 4

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
        % (ctrl, vhost, remote_tcp, remote_secure, TOKEN),
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
%s
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

# Exercises transport.useEncryption and transport.useCompression, which wrap the
# work connection with the same cipher and the snappy framed format.
[[proxies]]
name = "secure-echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
transport.useEncryption = true
transport.useCompression = true
"""
        % (
            ctrl,
            client_extra,
            TOKEN,
            LOCAL_TCP,
            remote_tcp,
            LOCAL_UDP,
            remote_udp,
            LOCAL_HTTP,
            LOCAL_SECURE,
            remote_secure,
        ),
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

    ok, detail = tcp_roundtrip(remote_secure, b"encrypted")
    check(label, "tcp with useEncryption + useCompression", ok, detail)

    # Compression only pays off on a payload bigger than one frame.
    ok, detail = tcp_bulk_roundtrip(remote_secure, 262144)
    check(label, "256 KiB over the compressed work connection", ok, detail)

    frpc.stop()
    frps.stop()



def run_visitor_pair(frps_exe, provider_exe, visitor_exe, label, base):
    """An stcp proxy served by one implementation and visited by the other."""
    ctrl = base
    visitor_port = base + 1
    secret = "shared-secret"

    print("")
    print("== %s ==" % label)
    print("   frps     %s" % frps_exe)
    print("   provider %s" % provider_exe)
    print("   visitor  %s" % visitor_exe)

    frps = Node(
        frps_exe,
        "frps",
        """bindAddr = "127.0.0.1"
bindPort = %d

[auth]
method = "token"
token = "%s"
"""
        % (ctrl, TOKEN),
        label,
    ).start()
    if not wait_for_port(ctrl):
        check(label, "server listening", False, frps.tail(15))
        frps.stop()
        return

    provider = Node(
        provider_exe,
        "frpc",
        """serverAddr = "127.0.0.1"
serverPort = %d

[auth]
method = "token"
token = "%s"

[[proxies]]
name = "secret"
type = "stcp"
localIP = "127.0.0.1"
localPort = %d
secretKey = "%s"
"""
        % (ctrl, TOKEN, LOCAL_TCP, secret),
        label + "-provider",
    ).start()
    time.sleep(2.0)

    visitor = Node(
        visitor_exe,
        "frpc",
        """serverAddr = "127.0.0.1"
serverPort = %d

[auth]
method = "token"
token = "%s"

[[visitors]]
name = "secret-visitor"
type = "stcp"
serverName = "secret"
secretKey = "%s"
bindAddr = "127.0.0.1"
bindPort = %d
"""
        % (ctrl, TOKEN, secret, visitor_port),
        label + "-visitor",
    ).start()

    if not wait_for_port(visitor_port, timeout=25):
        check(label, "visitor bound its port", False)
        print("   --- visitor log ---")
        print("   " + visitor.tail(20).replace("\n", "\n   "))
        print("   --- provider log ---")
        print("   " + provider.tail(20).replace("\n", "\n   "))
        print("   --- frps log ---")
        print("   " + frps.tail(20).replace("\n", "\n   "))
    else:
        check(label, "visitor bound its port", True)
        ok, detail = tcp_roundtrip(visitor_port, b"through-visitor")
        check(label, "stcp traffic reaches the provider", ok, detail)
        if ok:
            ok2, detail2 = tcp_roundtrip(visitor_port, b"second")
            check(label, "second visitor connection", ok2, detail2)

    visitor.stop()
    provider.stop()
    frps.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, help="path to the rust-frp binary")
    parser.add_argument("--upstream", required=True, help="frp release directory")
    parser.add_argument(
        "--with-visitors",
        action="store_true",
        help="also run the stcp visitor combinations",
    )
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
    for target, port in (
        (tcp_echo, LOCAL_TCP),
        (udp_echo, LOCAL_UDP),
        (http_echo, LOCAL_HTTP),
        (tcp_echo, LOCAL_SECURE),
    ):
        threading.Thread(target=target, args=(port, stop), daemon=True).start()
    time.sleep(0.4)

    tls_client = "\n[transport.tls]\nenable = true\n"
    # The upstream client has TLS on by default, so pairing it with our server
    # already covers "upstream TLS client"; the extra entry covers ours against
    # the upstream server.
    combos = [
        ("rust-frps+frpc", rust, up_frpc, 31000, ""),
        ("frps+rust-frpc", up_frps, rust, 31100, ""),
        ("rust-frps+rust-frpc", rust, rust, 31200, ""),
        ("frps+frpc", up_frps, up_frpc, 31300, ""),
        ("frps+rust-frpc+tls", up_frps, rust, 31400, tls_client),
    ]
    wanted = args.only.split(",")
    try:
        for label, frps_exe, frpc_exe, base, extra in combos:
            if args.only != "all" and label not in wanted:
                continue
            run_pair(frps_exe, frpc_exe, label, base, extra)
        if args.with_visitors:
            for vlabel, vfrps, vprovider, vvisitor, vbase in [
                ("stcp rust-frps rust->official", rust, rust, up_frpc, 32000),
                ("stcp rust-frps official->rust", rust, up_frpc, rust, 32100),
                ("stcp frps rust->official", up_frps, rust, up_frpc, 32200),
                ("stcp frps official->rust", up_frps, up_frpc, rust, 32300),
                ("stcp frps official->official", up_frps, up_frpc, up_frpc, 32400),
            ]:
                if args.only != "all" and vlabel not in wanted:
                    continue
                run_visitor_pair(vfrps, vprovider, vvisitor, vlabel, vbase)
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
