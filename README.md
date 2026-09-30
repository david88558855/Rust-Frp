# Rust-Frp

A Rust reimplementation of [frp](https://github.com/fatedier/frp) — a fast reverse proxy
that exposes services behind NAT or a firewall to the public internet.

**Compatibility target: frp `v0.71.0`.** Rust-Frp is being written to be *wire
compatible* with the reference Go implementation, so a Rust `frpc` can talk to an
upstream `frps` and vice versa.

> Status: **milestone 1** — protocol core. See [Roadmap](#roadmap).

---

## Wire protocol reference

Everything in `crates/frp-core` was derived from reading the upstream Go sources at
tag `v0.71.0`, not from guesswork. The behaviours deliberately reproduced:

| Concern | Upstream behaviour | Rust module |
| --- | --- | --- |
| Frame layout | `type: u8 \|\| len: i64 big endian \|\| json` | `frp_core::codec` |
| Max payload | `10240` bytes (`golib/msg/json.defaultMaxMsgLength`) | `frp_core::codec::MAX_MSG_LENGTH` |
| Message set | 18 message types, bytes `o 1 p 2 c w r s v 3 h 4 u i n m 5 6` | `frp_core::msg` |
| Token auth | `hex(md5(token \|\| decimal(timestamp)))` | `frp_core::crypto::auth` |
| `useEncryption` | AES-128-CFB, key = `PBKDF2-HMAC-SHA1(token, "frp", 64, 16)`, random 16 byte IV prefix | `frp_core::crypto::cfb` |
| `useCompression` | Snappy **framed** stream, masked CRC-32C per chunk | `frp_core::crypto::snappy` |
| Wrapping order | `conn → encrypt → snappy` (compression is the outer layer) | `frp_core::crypto::stream` |
| TLS | custom first byte `0x17` distinguishes frp TLS from real TLS (`0x16`) | *(next milestone)* |

## Repository layout

```
crates/
  frp-core    protocol framing, message model, crypto, shared helpers
  frp-server  frps: listener, control session, port manager, proxy managers, admin API
  frp-client  frpc: connector, control session, proxies, visitors, plugins, admin UI
  frp-cli     rust-frp binary hosting the frps / frpc subcommands
```

## Building

```bash
cargo build --release          # produces target/release/rust-frp
cargo test --workspace         # protocol, crypto and framing unit tests
./target/release/rust-frp info # wire compatibility summary
./target/release/rust-frp selftest
```

CI (`.github/workflows/ci.yml`) runs `cargo check`, the test suite, clippy and a
release build matrix for Linux, Windows and macOS.

## Running the server

```toml
# frps.toml
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
subDomainHost = "example.com"
allowPorts = [{ start = 6000, end = 6010 }]
enablePrometheus = true

[auth]
method = "token"
token = "change-me"

[webServer]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "change-me"
```

```bash
./target/release/rust-frp frps --verify -c ./frps.toml   # validate only
./target/release/rust-frp frps -c ./frps.toml            # run
```

TLS is negotiated on the control port automatically: a self-signed
certificate is generated when `transport.tls.certFile`/`keyFile` are unset,
and `transport.tls.force = true` rejects plaintext clients. The dashboard and
admin API are served on `webServer` (`/`, `/api/serverinfo`, `/api/proxy`,
`/api/clients`, `/healthz`, plus `/metrics` when `enablePrometheus` is set).

The virtual host ports only route; they need no certificate of their own.
`vhostHTTPPort` serves `http` proxies by `Host`/location and `vhostHTTPSPort`
serves `https` proxies by SNI, forwarding the TLS stream untouched.

## Running the client

```toml
# frpc.toml
serverAddr = "127.0.0.1"
serverPort = 7000

[auth]
method = "token"
token = "change-me"

# Directories of extra proxy definitions can be pulled in with includes.
includes = ["./confd/*.toml"]

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "web"
type = "http"
localPort = 8080
customDomains = ["web.example.com"]

[[proxies]]
name = "dns"
type = "udp"
localPort = 53
remotePort = 6000

# Only reachable from another frpc running a matching visitor.
[[proxies]]
name = "secret"
type = "stcp"
localPort = 22
secretKey = "shared-with-the-visitor"

[[visitors]]
name = "secret-visitor"
type = "stcp"
serverName = "secret"
secretKey = "shared-with-the-visitor"
bindPort = 9000
```

```bash
./target/release/rust-frp frpc --verify -c ./frpc.toml   # validate only
./target/release/rust-frp frpc -c ./frpc.toml            # run
```

`transport.tcpMux` defaults to on, matching upstream, and multiplexes the
control connection and every work connection over one socket using yamux.
`transport.tls.enable = true` wraps the control connection in TLS; the
obfuscated first byte behaviour and the "no `trustedCaFile` means accept any
certificate" rule are both reproduced, so a stock frps works out of the box.

`transport.protocol` accepts only `tcp` for now; `websocket`, `wss`, `kcp`
and `quic`, wire protocol `v2`, and the `xtcp`/`sudp` visitors are rejected at
configuration load time rather than silently misbehaving.

## Testing

```bash
cargo test --workspace          # unit tests
cargo clippy --workspace --all-targets

cargo build --release
python3 tests/e2e/e2e.py        # defaults to target/release/rust-frp

# Wire compatibility against an upstream frp release of the same version.
python3 tests/interop/interop.py \
    --rust target/release/rust-frp \
    --upstream /path/to/frp_0.71.0_linux_amd64
```

The unit tests cover the protocol layer, the crypto streams, the routers and
each component in isolation. They cannot catch a mismatch between the two
peers — a wrong assumption shared by a test and its implementation passes both
— so `tests/e2e/e2e.py` runs the built binary against itself and checks real
traffic through the tunnel: `tcp`, `udp` and an `http` virtual host over a yamux
session, the same with `tcpMux` off, TLS on the control port, and an `stcp`
visitor tunnelling to another client's proxy. It is part of CI.

`tests/interop/interop.py` goes further and runs the Rust peer against an
upstream frp release in all four combinations (Rust↔upstream in both
directions, plus Rust↔Rust and upstream↔upstream as controls). It needs a
release tarball from the frp project, so it is not part of CI, but it is the
check that matters most for compatibility: a detail both Rust peers get wrong
the same way is invisible to the e2e suite. The AES key salt was exactly that
kind of bug.

## Wire compatibility

Verified by running the Rust binary against the official `frp_0.71.0` release,
one as the server and one as the client, over loopback. `tests/interop/interop.py`
runs the matrix; the results below are from a run on Windows with both peers
built from this repository and upstream v0.71.0.

| server | client | tcp | udp | http vhost | `useEncryption` + `useCompression` | 256 KiB payload |
|---|---|---|---|---|---|---|
| rust-frps | frpc 0.71.0 | ok | ok | ok | ok | ok |
| frps 0.71.0 | rust-frpc | ok | ok | ok | ok | ok |
| frps 0.71.0 | rust-frpc (`transport.tls.enable`) | ok | ok | ok | ok | ok |
| rust-frps | rust-frpc | ok | ok | ok | ok | ok |
| frps 0.71.0 | frpc 0.71.0 (control) | ok | ok | ok | ok | ok |

`stcp`, exercised with the proxy served by one implementation and visited by
the other, in both directions and against both servers: ok (50/50 checks in
total).

What that covers: the frame format, the token signature, the AES-128-CFB
control stream, yamux multiplexing in both roles, the `0x17` TLS negotiation in
both directions, the work-connection handshake, the work-connection cipher and
the snappy framed stream, the visitor signature and the secret-key-based
visitor payload encryption, and `http` virtual host routing.

Not covered yet: `xtcp` and `sudp` visitors, `tcpmux`, proxy groups, bandwidth
limiting, client side plugins, and the `websocket` / `wss` / `kcp` / `quic`
transports, none of which are implemented.

## Roadmap

- [x] **M1 — protocol core**: message model, framing, token auth, AES-128-CFB
      encryption, Snappy framing, async stream adapters, offline self tests.
- [ ] **M2 — frps**
  - [x] TLS aware control listener (custom `0x17` first byte), token auth,
        run-id replacement, heartbeat supervision, work-connection pool,
        `NewProxy` / `CloseProxy`;
  - [x] `tcp`, `udp`, `stcp`, `sudp` proxies, port manager with `allowPorts`;
  - [x] visitor admission for `stcp` / `sudp`;
  - [x] `http` / `https` virtual host routing on `vhostHTTPPort` /
        `vhostHTTPSPort`: HTTP is terminated and replayed over a work
        connection (host rewrite, `X-Forwarded-For`, request/response header
        policies, basic auth, `CONNECT` tunnelling, custom 404); HTTPS routes on
        the SNI of a peeked ClientHello and forwards the still-encrypted stream
        so TLS terminates end to end at the backend;
  - [x] dashboard, JSON admin API, Prometheus endpoint;
  - [ ] `tcpmux`, `xtcp` NAT hole punching, proxy groups, bandwidth limiting.
- [x] **M3 — frpc**
  - [x] configuration loading (TOML/YAML/JSON + `includes`, `start` whitelist,
        duplicate name rejection);
  - [x] connector: TCP with optional TLS (custom `0x17` first byte), and the
        yamux session that `transport.tcpMux` installs on both peers by default;
  - [x] control session: login, encrypted control stream, heartbeats,
        `NewProxy` registration, `ReqWorkConn` → `NewWorkConn` → `StartWorkConn`;
  - [x] `tcp`, `http`, `https`, `stcp`, `tcpmux` proxies (the general TCP path),
        `udp` and `sudp` over a framed UDP work connection;
  - [x] `stcp` visitor;
  - [x] local service health checks with the register/withdraw cycle;
  - [x] reconnect with exponential backoff and run-id reuse;
  - [x] `frpc --verify`;
  - [x] verified against the official frp `v0.71.0` release in both directions,
        including `useEncryption`/`useCompression`, TLS on either side, and
        `stcp` proxies served by one implementation and visited by the other;
  - [ ] `xtcp` and `sudp` visitors, proxy plugins, client admin UI and store,
        client side bandwidth limiting, the proxy protocol header, and the
        `websocket` / `wss` / `kcp` / `quic` transports.
- [ ] **M4 — plugins & store**: `unix_domain_socket`, `http_proxy`, `socks5`,
      `static_file`, `https2http`, `http2https`, `https2https`; client admin UI
      and persistent proxy store.
- [ ] **M5 — extended transports**: KCP, QUIC, wire protocol v2 (AEAD
      handshake), OIDC auth, SSH tunnel gateway.

CI runs the Rust peers against each other, which catches regressions where both
sides are ours. Compatibility with upstream is verified separately against a
real frp release — see **Wire compatibility** below — because a detail both Rust
peers get wrong the same way is invisible to any self contained test.

## License and attribution

Licensed under the Apache License, Version 2.0, matching upstream frp.

frp is Copyright the frp Authors and licensed under Apache-2.0. Rust-Frp is an
independent reimplementation; where behaviour is reproduced for compatibility the
corresponding upstream source is cited in module documentation.
