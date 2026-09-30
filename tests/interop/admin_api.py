#!/usr/bin/env python3
"""Wire-protocol differential for the frpc admin HTTP server.

The whole admin surface is a small JSON API behind optional Basic Auth. We boot
two frpcs against the same frps (Rust peer for one, upstream 0.71.0 for the
other), then walk the same script of requests against each and compare. The
status payload is normalised so that ``server_addr`` and the per-proxy
timestamps collapse to nothing, but the structural keys and the error envelope
shape stay verbatim: an error must serialise to ``{"Code":N,"Msg":"..."}``
because upstream's ``GeneralResponse`` has no JSON tags.

By default both peers are run and every request is asserted to match the
baseline. ``--only rust-fpc-only`` skips the baseline, ``--only
upstream-only`` runs only the baseline; the cross-peer comparison requires both.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, THIS_DIR)
import interop as I  # noqa: E402

ADMIN_PORT = 16400
CTRL_PORT = 16420
REMOTE_PORT_BASE = 16440


def request(
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def wait_for_admin(port: int, timeout: float = 20.0) -> bool:
    return I.wait_for_port(port, timeout)


def normalise_status(payload):
    if isinstance(payload, dict):
        return {k: normalise_status(v) for k, v in payload.items() if k != "server_addr"}
    if isinstance(payload, list):
        return [normalise_status(v) for v in payload]
    return payload


def assert_envelope(body: bytes, expected_code: int) -> dict:
    obj = json.loads(body)
    assert set(obj.keys()) == {"Code", "Msg"}, (
        f"error envelope keys: {sorted(obj.keys())}"
    )
    assert obj["Code"] == expected_code, f"Code={obj['Code']} msg={obj['Msg']}"
    return obj


def common_cfg(admin_port: int, server_port: int, remote_port: int) -> str:
    """A client config that exercises every admin surface that does not need a
    real backend service (admin-tcp runs against an unreachable local port --
    status records ``start error`` and that is what /api/status surfaces)."""
    lines = [
        'serverAddr = "127.0.0.1"',
        f"serverPort = {server_port}",
        "",
        "[webServer]",
        'addr = "127.0.0.1"',
        f"port = {admin_port}",
        'user = "admin"',
        'password = "secret"',
        "",
        "[auth]",
        'method = "token"',
        'token = "tok"',
        "",
        "[[proxies]]",
        'name = "admin-tcp"',
        'type = "tcp"',
        'localIP = "127.0.0.1"',
        "localPort = 1",  # deliberately closed
        f"remotePort = {remote_port}",
        "",
        "[[proxies]]",
        'name = "admin-http"',
        'type = "http"',
        "localPort = 1",
        'customDomains = ["admin.example"]',
        "",
        "[[proxies]]",
        'name = "admin-stcp"',
        'type = "stcp"',
        'localIP = "127.0.0.1"',
        "localPort = 1",
        'secretKey = "stcp-secret"',
        "",
        "[[visitors]]",
        'name = "admin-stcp-v"',
        'type = "stcp"',
        'serverName = "admin-stcp"',
        'secretKey = "stcp-secret"',
        'bindAddr = "127.0.0.1"',
        f"bindPort = {remote_port + 1}",
    ]
    return "\n".join(lines) + "\n"


AUTH = ("admin", "secret")


def run_script(admin_port: int) -> dict:
    fp: dict = {}

    s, _, b = request(admin_port, "GET", "/healthz")
    fp["healthz_status"] = s

    s, _, b = request(admin_port, "GET", "/api/status", auth=AUTH)
    obj = json.loads(b)
    fp["status_keys"] = sorted(obj.keys())
    fp["status_types"] = sorted(obj.keys())
    fp["status"] = normalise_status(obj)

    s, _, b = request(admin_port, "GET", "/api/reload", auth=AUTH)
    # Upstream's Reload handler returns (nil, nil) which becomes a bare 200 with
    # an empty body; nothing to parse.
    fp["reload_code"] = s
    if s != 200:
        assert_envelope(b, s)

    s, _, b = request(admin_port, "GET", "/api/proxy/admin-tcp/config", auth=AUTH)
    if s == 200:
        fp["proxy_config_keys"] = sorted(json.loads(b).keys())
    else:
        fp["proxy_config_code"] = s

    s, _, b = request(admin_port, "GET", "/api/visitor/admin-stcp-v/config", auth=AUTH)
    if s == 200:
        fp["visitor_config_keys"] = sorted(json.loads(b).keys())
    else:
        fp["visitor_config_code"] = s

    s, _, b = request(admin_port, "GET", "/api/proxy/missing/config", auth=AUTH)
    assert_envelope(b, s)
    fp["missing_proxy_code"] = s
    fp["missing_proxy_keys"] = sorted(json.loads(b).keys())

    # Both peers reject a malformed JSON body on the store create endpoint.
    s, _, b = request(
        admin_port,
        "POST",
        "/api/store/proxies",
        body=b"this-is-not-json",
        auth=AUTH,
    )
    assert_envelope(b, s)
    fp["bad_body_keys"] = sorted(json.loads(b).keys())

    body = json.dumps({
        "name": "store-add-tcp",
        "type": "tcp",
        "localPort": 1,
        "remotePort": 16448,
    }).encode()
    s, _, b = request(admin_port, "POST", "/api/store/proxies", body=body, auth=AUTH)
    fp["store_add_code"] = s
    s, _, b = request(admin_port, "POST", "/api/store/proxies", body=body, auth=AUTH)
    if s >= 400:
        assert_envelope(b, s)
        fp["store_add_dup_code"] = s

    s, _, b = request(
        admin_port, "GET", "/api/store/proxies/store-add-tcp", auth=AUTH
    )
    if s == 200:
        fp["store_get_keys"] = sorted(json.loads(b).keys())

    s, _, b = request(
        admin_port, "DELETE", "/api/store/proxies/store-add-tcp", auth=AUTH
    )
    fp["store_del_code"] = s

    s, _, b = request(admin_port, "GET", "/api/store/proxies", auth=AUTH)
    fp["store_list_code"] = s

    return fp


def auth_script(admin_port: int) -> dict:
    out: dict = {}
    s, h, b = request(admin_port, "GET", "/api/status", auth=("admin", "secret"))
    out["valid_auth_code"] = s
    s, h, b = request(
        admin_port, "GET", "/api/status", auth=("admin", "wrong")
    )
    out["bad_auth_code"] = s
    out["bad_auth_keys"] = sorted(json.loads(b).keys()) if b else []
    out["www_authenticate"] = h.get("www-authenticate", "")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rust", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument(
        "--only",
        choices=["both", "rust-fpc-only", "upstream-only"],
        default="both",
    )
    args = p.parse_args()

    rust = os.path.abspath(args.rust)
    upstream = os.path.abspath(args.upstream)

    upstream_dir = upstream
    upstream_binary_dir = upstream_dir
    rust_dir = os.path.dirname(rust)
    rust_binary = rust

    server_cfg = (
        'bindAddr = "127.0.0.1"\n'
        f"bindPort = {CTRL_PORT}\n"
        f"allowPorts = [\n  {{ start = {REMOTE_PORT_BASE}, end = {REMOTE_PORT_BASE + 29} }}\n]\n"
        "\n[auth]\n"
        'method = "token"\n'
        'token = "tok"\n'
    )
    server = I.Node(
        os.path.join(upstream_dir, "frps.exe" if os.name == "nt" else "frps"),
        "frps",
        server_cfg,
        "admin-server",
    ).start()
    I.wait_for_port(CTRL_PORT)
    print(f"admin: frps listening on {CTRL_PORT}", file=sys.stderr)

    fingerprints: dict = {}

    def run_peer(binary: str, log_prefix: str, name: str):
        cfg = common_cfg(ADMIN_PORT, CTRL_PORT, REMOTE_PORT_BASE)
        node = I.Node(binary, "frpc", cfg, log_prefix)
        node.start()
        if not wait_for_admin(ADMIN_PORT, timeout=30):
            print(node.tail(50), file=sys.stderr)
            raise SystemExit(f"{name}: admin port never opened")
        time.sleep(1.0)
        return node

    if args.only != "upstream-only":
        node = run_peer(rust_binary, "rust", "rust")
        fingerprints["rust"] = run_script(ADMIN_PORT)
        fingerprints["rust-auth"] = auth_script(ADMIN_PORT)
        node.stop()
        time.sleep(1.0)

    if args.only != "rust-fpc-only":
        binary = os.path.join(
            upstream_binary_dir, "frpc.exe" if os.name == "nt" else "frpc"
        )
        node = run_peer(binary, "upstream", "upstream")
        fingerprints["upstream"] = run_script(ADMIN_PORT)
        fingerprints["upstream-auth"] = auth_script(ADMIN_PORT)
        node.stop()

    server.stop()

    if args.only == "both" and "rust" in fingerprints and "upstream" in fingerprints:
        diffs = []
        for key, value in fingerprints["rust"].items():
            if key.endswith("-auth"):
                continue
            u = fingerprints["upstream"].get(key)
            if value != u:
                diffs.append((key, value, u))
        if diffs:
            print("DIFF FOUND", file=sys.stderr)
            for key, r, u in diffs:
                print(f"  {key}:\n    rust    = {r!r}\n    upstream = {u!r}", file=sys.stderr)
            return 2
        auth_diff = []
        for key, value in fingerprints["rust-auth"].items():
            u = fingerprints["upstream-auth"].get(key)
            if value != u:
                auth_diff.append((key, value, u))
        if auth_diff:
            print("AUTH DIFF FOUND", file=sys.stderr)
            for key, r, u in auth_diff:
                print(f"  {key}:\n    rust    = {r!r}\n    upstream = {u!r}", file=sys.stderr)
            return 2
        print("admin api: rust fingerprint matches upstream fingerprint", file=sys.stderr)

    print(json.dumps(fingerprints, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())