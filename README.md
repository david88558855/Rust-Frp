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
| `useEncryption` | AES-128-CFB, key = `PBKDF2-HMAC-SHA1(token, "crypto", 64, 16)`, random 16 byte IV prefix | `frp_core::crypto::cfb` |
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
- [ ] **M3 — frpc**: config loading (TOML/YAML/JSON + `includes`), connector
      (TCP/TLS/WebSocket), proxy managers, STCP/XTCP visitors, health checks,
      `reload` / `verify` / `status` / `stop`.
- [ ] **M4 — plugins & store**: `unix_domain_socket`, `http_proxy`, `socks5`,
      `static_file`, `https2http`, `http2https`, `https2https`; client admin UI
      and persistent proxy store.
- [ ] **M5 — extended transports**: KCP, QUIC, wire protocol v2 (AEAD
      handshake), OIDC auth, SSH tunnel gateway.

Interoperability is validated by running a Rust peer against an upstream frp binary
of the same version.

## License and attribution

Licensed under the Apache License, Version 2.0, matching upstream frp.

frp is Copyright the frp Authors and licensed under Apache-2.0. Rust-Frp is an
independent reimplementation; where behaviour is reproduced for compatibility the
corresponding upstream source is cited in module documentation.
