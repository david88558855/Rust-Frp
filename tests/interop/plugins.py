#!/usr/bin/env python3
"""Client plugin interoperability against an official frp release.

`interop.py` answers "do the two implementations speak the same protocol".
This one answers a different question: "does a plugin do the same thing with
the work connection, whichever implementation is driving it".

Every plugin is registered once, each on its own `tcp` proxy -- plus one
`https` vhost proxy for the shape upstream documents for `https2http` -- and
the whole lot is run against four pairs:

    frps+frpc            the baseline: whatever this does is right
    rust-frps+rust-frpc  both ends ours
    frps+rust-frpc       our client behind a real frp server
    rust-frps+frpc       the official client behind our server

Each scenario's probe reports two things:

  * named checks, whose expectations are read out of the upstream Go source in
    `pkg/plugin/client`, so they say *why* a result is right;
  * a `signature`, a canonical string of everything observable about the
    exchange, which must come out byte-identical in all four pairs.

The second one is the point of the exercise. A plugin can pass its unit tests
and the end-to-end suite and still differ from upstream in a way nothing
single-implementation can see -- which is exactly how the AES salt in
`frp-core/src/crypto/mod.rs` stayed wrong through 170 unit tests and 13 e2e
checks. Comparing against a live baseline is the only thing that catches it.

Usage:

    python3 tests/interop/plugins.py --rust target/release/rust-frp \
        --upstream /path/to/frp_0.71.0_windows_amd64

The upstream directory has to contain `frps`/`frpc` (`.exe` on Windows).
`openssl` is needed for the certificate the TLS scenarios use; those scenarios
are skipped without it. `--only` restricts the run to a subset of the pairs.
"""

import argparse
import base64
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

TOKEN = "interop-token"
DOMAIN = "plugin.test"
WORK = tempfile.mkdtemp(prefix="frp-plugins-")

results = []


def check(label, name, ok, detail=""):
    results.append((label, name, ok, detail))
    print(
        "  %-4s %-52s %s" % ("PASS" if ok else "FAIL", name, detail),
        flush=True,
    )


def note(text):
    print("       %s" % text, flush=True)


def summarise():
    failed = [r for r in results if not r[2]]
    print("")
    print("=== summary ===")
    print("%d/%d checks passed" % (len(results) - len(failed), len(results)))
    for label, name, _, detail in failed:
        print("  FAIL %s / %s :: %s" % (label, name, detail))
    return 1 if failed else 0


def indent(text, prefix="       "):
    return "\n".join(prefix + line for line in text.splitlines())


# ------------------------------------------------------------------ process plumbing


def find_binary(directory, name):
    for candidate in (name, name + ".exe"):
        path = os.path.join(directory, candidate)
        if os.path.exists(path):
            return path
    return None


def safe_name(label):
    """Labels are human readable; filenames must not contain spaces or `>`."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in label)


class Node:
    """One frps or frpc process, upstream or ours."""

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


def is_free(port):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def allocate(count, start):
    """Returns the base of `count` consecutive free ports, so a whole run's
    range can be reserved in one go instead of racing with itself."""
    for base in range(start, start + 500):
        if all(is_free(base + i) for i in range(count)):
            return base
    raise RuntimeError("no free %d-port block near %d" % (count, start))


# ------------------------------------------------------------------ local services


def http_echo_server(port, ready, use_tls=False, cert=None):
    """Echoes the method, path and headers back as JSON.

    The plugins under test are HTTP clients pointed at this, so the reply is
    the observation: whatever the plugin put in the request shows up here.
    """
    context = None
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert[0], cert[1])

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(64)
    ready.set()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(
            target=_http_echo_session, args=(conn, context), daemon=True
        ).start()


def _http_echo_session(conn, context):
    try:
        if context:
            conn = context.wrap_socket(conn, server_side=True)
        conn.settimeout(10)
        raw = _read_raw_request(conn)
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, path, _ = lines[0].decode(errors="replace").split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers.setdefault(name.decode(errors="replace").lower(), []).append(
                    value.decode(errors="replace").strip()
                )
        payload = json.dumps(
            {
                "method": method,
                "path": path,
                "headers": headers,
                "body": body.decode(errors="replace"),
                "tls": context is not None,
            }
        ).encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(payload), payload)
        )
    except Exception:  # noqa: BLE001 - a probe may hang up mid-request
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _read_raw_request(conn):
    """Reads a request head plus whatever body its Content-Length promises."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return data
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(rest) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


def raw_echo_server(port, ready):
    """Echoes whatever it receives; the `tls2raw` backend."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(64)
    ready.set()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=_raw_echo_session, args=(conn,), daemon=True).start()


def _raw_echo_session(conn):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ------------------------------------------------------------------ probes


def _request_bytes(port, method, path, host, headers):
    lines = ["%s %s HTTP/1.1" % (method, path)]
    lines.append("Host: %s" % (host or "127.0.0.1:%d" % port))
    for name, value in (headers or {}).items():
        lines.append("%s: %s" % (name, value))
    if method in ("POST", "PUT", "PATCH"):
        lines.append("Content-Length: 0")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _read_http(conn, method):
    # `method` has to reach HTTPResponse: without it a HEAD reply, which has no
    # body and no length, would be read until the connection closed.
    reader = http.client.HTTPResponse(conn, method=method)
    reader.begin()
    body = b"" if method == "HEAD" else reader.read()
    headers = {name.lower(): value for name, value in reader.getheaders()}
    return reader.status, headers, body


def http_request(port, method="GET", path="/", host=None, headers=None, timeout=10):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(_request_bytes(port, method, path, host, headers))
        return _read_http(conn, method)


def tls_socket(port, sni, timeout=10):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=sni)


def tls_request(port, sni, method="GET", path="/", host=None, headers=None, timeout=10):
    conn = tls_socket(port, sni, timeout)
    try:
        conn.settimeout(timeout)
        conn.sendall(_request_bytes(port, method, path, host, headers))
        return _read_http(conn, method)
    finally:
        conn.close()


def tls_echo(port, sni, payload, timeout=10):
    conn = tls_socket(port, sni, timeout)
    try:
        conn.settimeout(timeout)
        conn.sendall(payload)
        data = b""
        while len(data) < len(payload):
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        conn.close()


def socks5_connect(port, host, target_port, timeout=10):
    """Opens a SOCKS5 CONNECT (no authentication negotiated) and returns the
    raw socket, positioned just past the reply."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    conn.sendall(b"\x05\x01\x00")
    reply = conn.recv(2)
    if reply != b"\x05\x00":
        conn.close()
        raise OSError("socks5 greeting failed: %r" % (reply,))
    name = host.encode()
    conn.sendall(
        b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", target_port)
    )
    head = conn.recv(4)
    if len(head) < 4 or head[:2] != b"\x05\x00":
        conn.close()
        raise OSError("socks5 CONNECT failed: %r" % (head,))
    atyp = head[3]
    if atyp == 0x01:
        conn.recv(4)
    elif atyp == 0x03:
        conn.recv(conn.recv(1)[0])
    elif atyp == 0x04:
        conn.recv(16)
    conn.recv(2)
    return conn


def socks5_http_get(port, host, target_port, path="/"):
    conn = socks5_connect(port, host, target_port)
    try:
        conn.sendall(
            (
                "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
                % (path, host, target_port)
            ).encode()
        )
        return _read_until_close(conn)
    finally:
        conn.close()


def proxy_request(port, target, path="/", headers=None, credentials=None):
    """An absolute-form request, i.e. what a client sends to a forward proxy."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        request = "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (
            target,
            path,
            target,
        )
        if credentials:
            token = base64.b64encode(credentials.encode()).decode()
            request += "Proxy-Authorization: Basic %s\r\n" % token
        for name, value in (headers or {}).items():
            request += "%s: %s\r\n" % (name, value)
        conn.sendall((request + "\r\n").encode())
        return _read_until_close(conn)
    finally:
        conn.close()


def proxy_connect(port, target, path="/"):
    """A CONNECT tunnel, then a plain HTTP request inside it."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        conn.sendall(
            ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                raise OSError("CONNECT closed early: %r" % (head,))
            head += chunk
        status = int(head.split(b" ")[1])
        if status != 200:
            return status, {}
        conn.sendall(
            (
                "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                % (path, target)
            ).encode()
        )
        code, _, body = _read_until_close(conn)
        return status if code == 200 else code, json.loads(body) if body else {}
    finally:
        conn.close()


def _read_until_close(conn):
    """Reads a whole reply, using HTTPResponse so chunked encoding works."""
    conn.settimeout(10)
    reader = http.client.HTTPResponse(conn)
    reader.begin()
    body = reader.read()
    return reader.status, {k.lower(): v for k, v in reader.getheaders()}, body


# ------------------------------------------------------------------ scenarios


class Observation:
    """What one probe saw, split into named checks and a comparable summary."""

    def __init__(self):
        self.checks = []
        self.facts = []

    def check(self, name, ok, detail=""):
        self.checks.append((name, bool(ok), detail))

    def fact(self, *parts):
        self.facts.append("::".join("" if p is None else str(p) for p in parts))

    def signature(self):
        return " | ".join(self.facts)


def probe_http2http(ctx, port):
    obs = Observation()
    status, _, body = http_request(
        port, path="/probe", host="backend.invalid", headers={"X-Forwarded-For": "1.2.3.4"}
    )
    echo = json.loads(body)
    headers = echo["headers"]
    forwarded = sorted(name for name in headers if name.startswith("x-forwarded-"))
    obs.check(
        "http2http / forwards the request",
        status == 200 and echo["path"] == "/probe",
        "status=%s path=%s" % (status, echo.get("path")),
    )
    # `httputil.ReverseProxy` deletes the forwarding headers before `Rewrite`
    # runs, and the `http2http` rewrite puts none of them back.
    obs.check(
        "http2http / drops X-Forwarded-*",
        not forwarded,
        "leaked=%s" % forwarded,
    )
    # No `hostHeaderRewrite`, and the rewrite only assigns `URL.Host`, so the
    # backend still sees the Host the client asked for.
    obs.check(
        "http2http / keeps the inbound Host",
        headers.get("host") == ["backend.invalid"],
        "host=%s" % headers.get("host"),
    )
    obs.fact(status, echo["method"], echo["path"], headers.get("host"), forwarded, echo["tls"])
    return obs


def probe_http2https(ctx, port):
    obs = Observation()
    status, _, body = http_request(
        port, path="/probe", host="backend.invalid", headers={"X-Forwarded-For": "1.2.3.4"}
    )
    echo = json.loads(body)
    headers = echo["headers"]
    obs.check(
        "http2https / reaches a TLS backend",
        status == 200 and echo["tls"] is True,
        "status=%s tls=%s" % (status, echo.get("tls")),
    )
    # The one deliberate difference from `http2http`: this rewrite copies the
    # inbound forwarding headers back onto the outbound request.
    obs.check(
        "http2https / copies X-Forwarded-For back",
        headers.get("x-forwarded-for") == ["1.2.3.4"],
        "xff=%s" % headers.get("x-forwarded-for"),
    )
    obs.fact(
        status,
        echo["method"],
        echo["path"],
        headers.get("host"),
        headers.get("x-forwarded-for"),
        echo["tls"],
    )
    return obs


def probe_https2http(ctx, port):
    obs = Observation()
    # The SNI has to match the Host: upstream wraps this plugin's handler in
    # `withMisdirectedRequestCheck`, so anything else is a 421 -- asserted
    # separately below.
    status, _, body = tls_request(
        port, "front.example", path="/probe", host="front.example",
        headers={"X-Forwarded-For": "1.2.3.4"},
    )
    echo = json.loads(body)
    headers = echo["headers"]
    xff = headers.get("x-forwarded-for", [""])[0]
    obs.check(
        "https2http / terminates TLS",
        status == 200 and echo["tls"] is False,
        "status=%s backend-tls=%s" % (status, echo.get("tls")),
    )
    # `SetXForwarded` appends the client address to the chain the client sent.
    # The address comes from the `src_addr` the server put in `StartWorkConn`,
    # because this plugin's listener is the one built with `useSourceRemoteAddr`.
    obs.check(
        "https2http / appends the client to X-Forwarded-For",
        xff.startswith("1.2.3.4, "),
        "xff=%s" % xff,
    )
    obs.check(
        "https2http / reports the protocol",
        headers.get("x-forwarded-proto") == ["https"],
        "xfp=%s" % headers.get("x-forwarded-proto"),
    )
    obs.check(
        "https2http / reports the host",
        headers.get("x-forwarded-host") == ["front.example"],
        "xfh=%s" % headers.get("x-forwarded-host"),
    )
    misdirected = tls_request(port, "other.example", path="/probe", host="front.example")[0]
    obs.check(
        "https2http / refuses a mismatched SNI with 421",
        misdirected == 421,
        "status=%s" % misdirected,
    )
    obs.fact(
        status,
        echo["method"],
        echo["path"],
        xff,
        headers.get("x-forwarded-proto"),
        headers.get("x-forwarded-host"),
        echo["tls"],
        misdirected,
    )
    return obs


def probe_https2https(ctx, port):
    obs = Observation()
    status, _, body = tls_request(
        port, "front.example", path="/probe", host="front.example"
    )
    echo = json.loads(body)
    headers = echo["headers"]
    obs.check(
        "https2https / reaches a TLS backend",
        status == 200 and echo["tls"] is True,
        "status=%s backend-tls=%s" % (status, echo.get("tls")),
    )
    obs.check(
        "https2https / reports the protocol",
        headers.get("x-forwarded-proto") == ["https"],
        "xfp=%s" % headers.get("x-forwarded-proto"),
    )
    misdirected = tls_request(port, "other.example", path="/probe", host="front.example")[0]
    obs.check(
        "https2https / refuses a mismatched SNI with 421",
        misdirected == 421,
        "status=%s" % misdirected,
    )
    obs.fact(
        status,
        echo["method"],
        echo["path"],
        headers.get("x-forwarded-proto"),
        headers.get("x-forwarded-host"),
        echo["tls"],
        misdirected,
    )
    return obs


def probe_tls2raw(ctx, port):
    obs = Observation()
    payload = b"tls2raw-payload-0123456789"
    echoed = tls_echo(port, "any.sni", payload)
    obs.check(
        "tls2raw / forwards the decrypted bytes",
        echoed == payload,
        "got %r" % (echoed,),
    )
    obs.fact(echoed)
    return obs


def probe_static_file(ctx, port):
    obs = Observation()
    status, _, body = http_request(port, path="/hello.txt")
    obs.check(
        "static_file / serves a file",
        status == 200 and body == b"static-file-body\n",
        "status=%s body=%r" % (status, body),
    )
    missing = http_request(port, path="/missing.txt")[0]
    obs.check(
        "static_file / answers 404 for a missing path",
        missing == 404,
        "status=%s" % missing,
    )
    # The route is registered with `Methods("GET")`, and gorilla/mux answers
    # 405 -- not 200 -- for every other method, HEAD included.
    head = http_request(port, method="HEAD", path="/hello.txt")[0]
    obs.check("static_file / rejects HEAD with 405", head == 405, "status=%s" % head)
    post = http_request(port, method="POST", path="/hello.txt")[0]
    obs.check("static_file / rejects POST with 405", post == 405, "status=%s" % post)
    obs.fact(status, body, missing, head, post)
    return obs


def probe_static_file_auth(ctx, port):
    obs = Observation()
    unauth = http_request(port, path="/hello.txt")[0]
    obs.check(
        "static_file+auth / requires credentials", unauth == 401, "status=%s" % unauth
    )
    token = base64.b64encode(b"u:p").decode()
    status, _, body = http_request(
        port, path="/hello.txt", headers={"Authorization": "Basic " + token}
    )
    obs.check(
        "static_file+auth / accepts the right credentials",
        status == 200 and body == b"static-file-body\n",
        "status=%s" % status,
    )
    obs.fact(unauth, status, body)
    return obs


def probe_socks5(ctx, port):
    obs = Observation()
    status, _, body = socks5_http_get(port, "127.0.0.1", ctx["http_echo"], "/via-socks5")
    echo = json.loads(body)
    obs.check(
        "socks5 / carries a request through CONNECT",
        status == 200 and echo["path"] == "/via-socks5",
        "status=%s path=%s" % (status, echo.get("path")),
    )
    obs.fact(status, echo.get("method"), echo.get("path"))
    return obs


def probe_http_proxy(ctx, port):
    obs = Observation()
    target = "127.0.0.1:%d" % ctx["http_echo"]
    status, _, body = proxy_request(port, target, "/absolute-form")
    echo = json.loads(body)
    obs.check(
        "http_proxy / forwards an absolute-form request",
        status == 200 and echo["path"] == "/absolute-form",
        "status=%s path=%s" % (status, echo.get("path")),
    )
    status, echo = proxy_connect(port, target, "/through-connect")
    obs.check(
        "http_proxy / tunnels CONNECT",
        status == 200 and echo.get("path") == "/through-connect",
        "status=%s path=%s" % (status, echo.get("path")),
    )
    obs.fact(status, echo.get("path"))
    return obs


def probe_http_proxy_auth(ctx, port):
    obs = Observation()
    target = "127.0.0.1:%d" % ctx["http_echo"]
    denied = proxy_request(port, target)[0]
    obs.check(
        "http_proxy+auth / rejects an unauthenticated request with 407",
        denied == 407,
        "status=%s" % denied,
    )
    allowed = proxy_request(port, target, credentials="u:p")[0]
    obs.check(
        "http_proxy+auth / accepts the right credentials",
        allowed == 200,
        "status=%s" % allowed,
    )
    obs.fact(denied, allowed)
    return obs


def toml_string(value):
    """Renders a string for TOML without letting a Windows path be read as an
    escape sequence: a backslash in `"C:\\tmp"` starts an invalid `\\u` escape,
    while a TOML literal string in single quotes takes it verbatim."""
    if "'" in value:
        return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    return "'%s'" % value


def fragment(name, **values):
    lines = ['type = "%s"' % name]
    for key, value in values.items():
        if isinstance(value, int):
            lines.append("%s = %d" % (key, value))
        else:
            lines.append("%s = %s" % (key, toml_string(value)))
    return "\n".join(lines)


SCENARIOS = [
    {
        "name": "http2http",
        "needs_cert": False,
        "probe": probe_http2http,
        "fragment": lambda ports, cert: fragment(
            "http2http", localAddr="127.0.0.1:%d" % ports["http_echo"]
        ),
    },
    {
        "name": "http2https",
        "needs_cert": False,
        "probe": probe_http2https,
        "fragment": lambda ports, cert: fragment(
            "http2https", localAddr="127.0.0.1:%d" % ports["https_echo"]
        ),
    },
    {
        "name": "https2http",
        "needs_cert": True,
        "probe": probe_https2http,
        "fragment": lambda ports, cert: fragment(
            "https2http",
            localAddr="127.0.0.1:%d" % ports["http_echo"],
            crtPath=cert[0],
            keyPath=cert[1],
        ),
    },
    {
        "name": "https2https",
        "needs_cert": True,
        "probe": probe_https2https,
        "fragment": lambda ports, cert: fragment(
            "https2https",
            localAddr="127.0.0.1:%d" % ports["https_echo"],
            crtPath=cert[0],
            keyPath=cert[1],
        ),
    },
    {
        "name": "tls2raw",
        "needs_cert": True,
        "probe": probe_tls2raw,
        "fragment": lambda ports, cert: fragment(
            "tls2raw",
            localAddr="127.0.0.1:%d" % ports["raw_echo"],
            crtPath=cert[0],
            keyPath=cert[1],
        ),
    },
    {
        "name": "static_file",
        "needs_cert": False,
        "probe": probe_static_file,
        "fragment": lambda ports, cert: fragment(
            "static_file", localPath=ports["root"]
        ),
    },
    {
        "name": "static_file_auth",
        "needs_cert": False,
        "probe": probe_static_file_auth,
        "fragment": lambda ports, cert: fragment(
            "static_file", localPath=ports["root"], httpUser="u", httpPassword="p"
        ),
    },
    {
        "name": "socks5",
        "needs_cert": False,
        "probe": probe_socks5,
        "fragment": lambda ports, cert: fragment("socks5"),
    },
    {
        "name": "http_proxy",
        "needs_cert": False,
        "probe": probe_http_proxy,
        "fragment": lambda ports, cert: fragment("http_proxy"),
    },
    {
        "name": "http_proxy_auth",
        "needs_cert": False,
        "probe": probe_http_proxy_auth,
        "fragment": lambda ports, cert: fragment(
            "http_proxy", httpUser="u", httpPassword="p"
        ),
    },
]


def active_scenarios(cert):
    return [scene for scene in SCENARIOS if cert is not None or not scene["needs_cert"]]


# ------------------------------------------------------------------ configuration


def server_config(ports):
    return (
        'bindAddr = "127.0.0.1"\n'
        "bindPort = %d\n"
        "vhostHTTPSPort = %d\n"
        "allowPorts = [{ start = %d, end = %d }]\n"
        "\n[auth]\n"
        'method = "token"\n'
        'token = "%s"\n'
        % (
            ports["ctrl"],
            ports["vhost_https"],
            ports["remote_base"],
            ports["remote_base"] + 40,
            TOKEN,
        )
    )


def client_config(ports, cert):
    scenes = active_scenarios(cert)
    parts = [
        'serverAddr = "127.0.0.1"\n',
        "serverPort = %d\n" % ports["ctrl"],
        "\n[auth]\n",
        'method = "token"\n',
        'token = "%s"\n' % TOKEN,
    ]
    for index, scene in enumerate(scenes):
        parts.append(
            "\n[[proxies]]\n"
            'name = "%s"\n'
            'type = "tcp"\n'
            'localIP = "127.0.0.1"\n'
            "localPort = %d\n"
            "remotePort = %d\n"
            "\n[proxies.plugin]\n%s\n"
            % (
                scene["name"],
                ports["local_base"] + index,
                ports["remote_base"] + index,
                scene["fragment"](ports, cert),
            )
        )
    if cert is not None:
        # The shape upstream documents for `https2http`: an `https` proxy on
        # the vhost port, routed by SNI, rather than a bare `tcp` one.
        parts.append(
            "\n[[proxies]]\n"
            'name = "vhost-https"\n'
            'type = "https"\n'
            'customDomains = ["%s"]\n'
            "\n[proxies.plugin]\n"
            "%s\n"
            % (
                DOMAIN,
                fragment(
                    "https2http",
                    localAddr="127.0.0.1:%d" % ports["http_echo"],
                    crtPath=cert[0],
                    keyPath=cert[1],
                ),
            )
        )
    return "".join(parts)


def build_certificate():
    crt = os.path.join(WORK, "plugin.crt")
    key = os.path.join(WORK, "plugin.key")
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", crt, "-days", "2", "-nodes",
            "-subj", "/CN=%s" % DOMAIN,
            "-addext", "subjectAltName=DNS:%s,IP:127.0.0.1" % DOMAIN,
        ],
        capture_output=True,
        cwd=WORK,
    )
    if result.returncode != 0:
        raise RuntimeError("openssl failed: %s" % result.stderr.decode(errors="replace"))
    return crt, key


# ------------------------------------------------------------------ runner


def compare(label, name, value, baseline):
    expected = baseline.get(name)
    if expected is None:
        baseline[name] = value
        note("baseline %-20s %s" % (name, value))
        return
    check(
        label,
        "%s / matches the frps+frpc baseline" % name,
        value == expected,
        "" if value == expected else "got %s, baseline %s" % (value, expected),
    )


def run_matrix(label, frps_exe, frpc_exe, cert, services, base, baseline):
    scenes = active_scenarios(cert)
    ports = {
        "ctrl": base,
        "vhost_https": base + 1,
        "remote_base": base + 2,
        "local_base": base + 2 + len(SCENARIOS) + 2,
    }
    ports.update(services)

    print("")
    print("== %s ==" % label)
    print("   frps %s" % frps_exe)
    print("   frpc %s" % frpc_exe)

    frps = Node(frps_exe, "frps", server_config(ports), label).start()
    if not wait_for_port(ports["ctrl"]):
        check(label, "server listening", False, "see the log")
        print(indent(frps.tail(20)))
        frps.stop()
        return

    frpc = Node(frpc_exe, "frpc", client_config(ports, cert), label).start()
    try:
        if not wait_for_port(ports["remote_base"], timeout=25):
            check(label, "proxies registered", False, "see the logs")
            print("   --- frpc ---\n%s" % indent(frpc.tail(20)))
            print("   --- frps ---\n%s" % indent(frps.tail(20)))
            return
        check(label, "proxies registered", True)

        ctx = {"http_echo": services["http_echo"], "https_echo": services["https_echo"]}
        for index, scene in enumerate(scenes):
            port = ports["remote_base"] + index
            name = scene["name"]
            if not wait_for_port(port, timeout=10):
                check(label, "%s / remote port opened" % name, False, "port %d" % port)
                continue
            try:
                observation = scene["probe"](ctx, port)
            except Exception as exc:  # noqa: BLE001 - a probe failure is a result
                check(label, name, False, "%s: %s" % (type(exc).__name__, exc))
                continue
            for check_name, ok, detail in observation.checks:
                check(label, check_name, ok, detail)
            compare(label, name, observation.signature(), baseline)

        # The `https` vhost shape.
        if cert is not None:
            name = "https-vhost"
            try:
                status, _, body = tls_request(
                    ports["vhost_https"], DOMAIN, path="/vhost", host=DOMAIN
                )
                echo = json.loads(body)
                check(
                    label,
                    "https vhost / routes to the https2http plugin",
                    status == 200 and echo.get("path") == "/vhost",
                    "status=%s path=%s" % (status, echo.get("path")),
                )
                compare(label, name, "%s::%s" % (status, echo.get("path")), baseline)
            except Exception as exc:  # noqa: BLE001
                check(label, "https vhost / routes to the https2http plugin", False, str(exc))
    finally:
        frpc.stop()
        frps.stop()


def allocate_services():
    base = allocate(6, 38000)
    services = {
        "http_echo": base,
        "https_echo": base + 2,
        "raw_echo": base + 4,
    }
    services["root"] = os.path.join(WORK, "webroot")
    os.makedirs(services["root"], exist_ok=True)
    # Binary mode on purpose: text mode would turn the newline into CRLF on
    # Windows and the file would no longer match what the probes expect.
    with open(os.path.join(services["root"], "hello.txt"), "wb") as fh:
        fh.write(b"static-file-body\n")
    return services


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rust", required=True, help="path to the rust-frp binary")
    parser.add_argument("--upstream", required=True, help="frp release directory")
    parser.add_argument(
        "--only",
        default="all",
        help="comma separated subset of frps+frpc,rust-frps+rust-frpc,"
        "frps+rust-frpc,rust-frps+frpc",
    )
    args = parser.parse_args()

    rust = os.path.abspath(args.rust)
    if not os.path.exists(rust):
        print("missing rust binary at %s" % rust)
        return 1
    up_frps = find_binary(args.upstream, "frps")
    up_frpc = find_binary(args.upstream, "frpc")
    if not up_frps or not up_frpc:
        print("no frps/frpc in %s" % args.upstream)
        return 1

    upstream_version = subprocess.run(
        [up_frps, "--version"], capture_output=True, text=True
    ).stdout.strip()
    rust_version = subprocess.run(
        [rust, "info"], capture_output=True, text=True
    ).stdout.splitlines()
    print("rust     : %s" % (rust_version[0] if rust_version else "?"))
    print("upstream : %s" % upstream_version)
    if "0.71.0" not in upstream_version:
        print("WARNING: upstream is not v0.71.0; the comparison may not be meaningful")

    cert = build_certificate() if shutil.which("openssl") else None
    if cert is None:
        print("openssl is not on PATH: the TLS scenarios will be skipped")

    services = allocate_services()
    ready = threading.Event()
    threads = [
        threading.Thread(
            target=http_echo_server, args=(services["http_echo"], ready), daemon=True
        ),
        threading.Thread(
            target=raw_echo_server, args=(services["raw_echo"], ready), daemon=True
        ),
    ]
    if cert is not None:
        threads.append(
            threading.Thread(
                target=http_echo_server,
                args=(services["https_echo"], ready),
                kwargs={"use_tls": True, "cert": cert},
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()
    if not ready.wait(5):
        print("the local echo services did not start")
        return 1
    time.sleep(0.3)

    combos = [
        ("frps+frpc", up_frps, up_frpc, 25000),
        ("rust-frps+rust-frpc", rust, rust, 26000),
        ("frps+rust-frpc", up_frps, rust, 27000),
        ("rust-frps+frpc", rust, up_frpc, 28000),
    ]
    wanted = args.only.split(",")
    # The baseline has to run first: it is what the others are compared to.
    baseline = {}
    for label, frps_exe, frpc_exe, base in combos:
        if args.only != "all" and label not in wanted:
            continue
        run_matrix(label, frps_exe, frpc_exe, cert, services, base, baseline)

    code = summarise()
    print("logs and certificate are in %s" % WORK)
    return code


if __name__ == "__main__":
    sys.exit(main())
