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
```

The unit tests cover the protocol layer, the crypto streams, the routers and
each component in isolation. They cannot catch a mismatch between the two
peers — a wrong assumption shared by a test and its implementation passes both
— so `tests/e2e/e2e.py` runs the built binary against itself and checks real
traffic through the tunnel: `tcp`, `udp` and an `http` virtual host over a yamux
session, the same with `tcpMux` off, TLS on the control port, and an `stcp`
visitor tunnelling to another client's proxy. It is part of CI.

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
  - [ ] `xtcp` and `sudp` visitors, proxy plugins, client admin UI and store,
        client side bandwidth limiting, the proxy protocol header, and the
        `websocket` / `wss` / `kcp` / `quic` transports.
- [ ] **M4 — plugins & store**: `unix_domain_socket`, `http_proxy`, `socks5`,
      `static_file`, `https2http`, `http2https`, `https2https`; client admin UI
      and persistent proxy store.
- [ ] **M5 — extended transports**: KCP, QUIC, wire protocol v2 (AEAD
      handshake), OIDC auth, SSH tunnel gateway.

CI runs the Rust peers against each other, which is what catches regressions in
the parts of the protocol where both sides are ours. Wire compatibility with
upstream frp is derived from the upstream v0.71.0 sources — frame layout, token
and visitor signatures, cipher and compression choices, control-connection
encryption, TLS first byte, yamux framing — and the next verification step is to
run a Rust peer against an upstream frp binary of the same version, in both
directions.

## License and attribution

Licensed under the Apache License, Version 2.0, matching upstream frp.

frp is Copyright the frp Authors and licensed under Apache-2.0. Rust-Frp is an
independent reimplementation; where behaviour is reproduced for compatibility the
corresponding upstream source is cited in module documentation.
