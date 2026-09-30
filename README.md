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

## Roadmap

- [x] **M1 — protocol core**: message model, framing, token auth, AES-128-CFB
      encryption, Snappy framing, async stream adapters, offline self tests.
- [ ] **M2 — frps**: TLS aware listener, control session, run-id management,
      work-connection pool, port manager with `allowPorts`, TCP/UDP/HTTP/HTTPS/STCP
      proxy managers, `vhost` router, admin API, Prometheus metrics, dashboard.
- [ ] **M3 — frpc**: config loading (TOML/YAML/JSON + `includes`), connector
      (TCP/TLS/WebSocket), proxy managers, STCP/XTCP visitors, health checks,
      bandwidth limits, proxy protocol, `reload` / `verify` / `status` / `stop`.
- [ ] **M4 — plugins & store**: `unix_domain_socket`, `http_proxy`, `socks5`,
      `static_file`, `https2http`, `http2https`, `https2https`; client admin UI and
      persistent proxy store.
- [ ] **M5 — extended transports**: tcpmux, SUDP, XTCP NAT hole punching, KCP, QUIC,
      wire protocol v2 (AEAD handshake), OIDC auth, SSH tunnel gateway.

Interoperability is validated by running a Rust peer against an upstream frp binary
of the same version.

## License and attribution

Licensed under the Apache License, Version 2.0, matching upstream frp.

frp is Copyright the frp Authors and licensed under Apache-2.0. Rust-Frp is an
independent reimplementation; where behaviour is reproduced for compatibility the
corresponding upstream source is cited in module documentation.
