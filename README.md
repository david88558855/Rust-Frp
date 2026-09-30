# Rust-Frp

**[简体中文](#简体中文) ｜ [English](#english)**

---

## 简体中文

一个用 Rust 重写的 [frp](https://github.com/fatedier/frp)：把位于 NAT 或防火墙之后的服务暴露到公网的反向代理。

**兼容目标：frp `v0.71.0`。** 目标是与官方 Go 实现**线协议兼容** —— Rust 版 `frpc` 能直接连上游 `frps`，反之亦然。

> 状态：**M1 协议核心、M2 frps、M3 frpc 均已完成**；M4（客户端 Store / Admin UI）与 M5（扩展传输）尚未开始。详见下文「路线图」。

### 线协议对照

`crates/frp-core` 中的全部内容都来自阅读上游 Go 源码（tag `v0.71.0`），不是猜测。刻意复刻的行为如下：

| 关注点 | 上游行为 | Rust 模块 |
| --- | --- | --- |
| 帧格式 | `type: u8 \|\| len: i64 大端 \|\| json` | `frp_core::codec` |
| 最大载荷 | `10240` 字节（`golib/msg/json.defaultMaxMsgLength`） | `frp_core::codec::MAX_MSG_LENGTH` |
| 消息集合 | 18 种消息类型，字节为 `o 1 p 2 c w r s v 3 h 4 u i n m 5 6` | `frp_core::msg` |
| Token 认证 | `hex(md5(token \|\| 十进制(timestamp)))` | `frp_core::crypto::auth` |
| `useEncryption` | AES-128-CFB，密钥 = `PBKDF2-HMAC-SHA1(token, "frp", 64, 16)`，前置 16 字节随机 IV | `frp_core::crypto::cfb` |
| `useCompression` | Snappy **framed** 流，每块带掩码的 CRC-32C | `frp_core::crypto::snappy` |
| 包装顺序 | `conn → encrypt → snappy`（压缩在外层） | `frp_core::crypto::stream` |
| TLS | 自定义首字节 `0x17` 区分 frp TLS 与真 TLS（`0x16`） | `frp_core::transport`、`frp_core::tls_sni` |
| TCP 多路复用 | yamux，`transport.tcpMux` 两端默认开启 | `frp_core::yamux` |
| 虚拟主机路由 | `Host` / location 与 SNI 路由，`*` catch-all | `frp_core::vhost` |

⚠️ 关于加密密钥有一个极易搞错的常量：`golib/crypto` 里 `DefaultSalt = "crypto"` 是**库**的默认值，
但 frp 在自己的 `init()` 里把它覆写成了 `"frp"`。照抄 golib 会得到一套自洽但与官方不通的密钥 ——
自家两端正常，与官方两端都断在明文 `Login` 之后。

### 仓库结构

```
crates/
  frp-core   协议分帧、消息模型、加密、公共辅助
  frp-server  frps：监听、控制会话、端口管理、各类代理、Admin API
  frp-client  frpc：连接器、控制会话、代理、visitor、插件、Admin UI
  frp-cli     rust-frp 可执行文件，承载 frps / frpc 两个子命令
```

### 构建

```bash
cargo build --release          # 产出 target/release/rust-frp
cargo test --workspace         # 协议、加密与分帧单元测试
./target/release/rust-frp info # 线协议兼容性摘要
./target/release/rust-frp selftest
```

CI（`.github/workflows/ci.yml`）会跑 `cargo check`、测试、clippy，以及 Linux / Windows / macOS
三平台的 release 构建矩阵，外加端到端与差分验证两个作业。

### 运行服务端

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
./target/release/rust-frp frps --verify -c ./frps.toml   # 仅校验配置
./target/release/rust-frp frps -c ./frps.toml            # 启动
```

控制端口上的 TLS 会自动协商：未设置 `transport.tls.certFile`/`keyFile` 时生成自签名证书，
`transport.tls.force = true` 会拒绝明文客户端。面板与 Admin API 挂在 `webServer` 上
（`/`、`/api/serverinfo`、`/api/proxy`、`/api/clients`、`/healthz`，以及设置了
`enablePrometheus` 时的 `/metrics`）。

虚拟主机端口只做路由，自身不需要证书。`vhostHTTPPort` 按 `Host`/location 服务 `http` 代理，
`vhostHTTPSPort` 按 SNI 服务 `https` 代理，并把 TLS 流原样转发（不在服务端终结 TLS）。

### 运行客户端

```toml
# frpc.toml
serverAddr = "127.0.0.1"
serverPort = 7000

[auth]
method = "token"
token = "change-me"

# 可以用 includes 引入其它目录下的代理定义。
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

# 只有运行了对应 visitor 的另一个 frpc 才能访问。
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
./target/release/rust-frp frpc --verify -c ./frpc.toml   # 仅校验配置
./target/release/rust-frp frpc -c ./frpc.toml            # 启动
```

`transport.tcpMux` 与上游一致，默认开启，用 yamux 把控制连接和所有 work 连接复用到一条 socket 上。
`transport.tls.enable = true` 会把控制连接包进 TLS；伪装首字节的行为，以及
「没有 `trustedCaFile` 就接受任意证书」这条规则都已复刻，所以默认配置的 frps 开箱即可连上。

`transport.protocol` 目前只接受 `tcp`；`websocket`、`wss`、`kcp`、`quic`、线协议 `v2`，
以及 `xtcp`/`sudp` visitor 都会在配置加载阶段直接报错，而不是悄悄跑错。

### 测试

```bash
cargo test --workspace          # 单元测试
cargo clippy --workspace --all-targets

cargo build --release
python3 tests/e2e/e2e.py        # 默认使用 target/release/rust-frp

# 与同版本官方 frp 发行包做差分验证。
python3 tests/interop/interop.py \
    --rust target/release/rust-frp \
    --upstream /path/to/frp_0.71.0_linux_amd64 \
    --with-visitors
python3 tests/interop/plugins.py \
    --rust target/release/rust-frp \
    --upstream /path/to/frp_0.71.0_linux_amd64
```

单元测试覆盖协议层、加密流、路由器以及各组件的独立行为。它们**发现不了两端之间的不一致** ——
测试和实现共享同一个错误假设时，两边都会通过 —— 所以 `tests/e2e/e2e.py` 让编译产物自己和自己跑，
在隧道上验证真实流量：走 yamux 会话的 `tcp`、`udp` 和一个 `http` 虚拟主机，关掉 `tcpMux` 的同样一组，
控制端口开启 TLS，以及一个 `stcp` visitor 打通到另一个客户端的代理。

这两层都发现不了**两端共同犯的错**，因此还有第三层。`tests/interop/interop.py` 用真实 frp 发行包
跑全部四种组合（Rust↔上游双向，外加 Rust↔Rust 与上游↔上游作为对照）。`tests/interop/plugins.py`
对客户端插件做同样的事：十一个场景，每个实现各注册一次，用完全相同的探针探测，
并把每一个可观测结果与**活着的** `frps`+`frpc` 基线比对，而不是与此处写下的某个值比对。

最后这一点不是装饰。TLS 终结类插件的那道「请求被误导」校验在本项目里是缺失的：
没有它，一个 SNI 与 Host 不匹配的请求会被正常服务而不是被拒绝，而单元测试与端到端测试都没有察觉。
更早的时候，AES 密钥的盐错了整整一个里程碑 —— 170 个单元测试、13 项端到端检查全部通过，
因为两端错得一模一样。现在这两层都在 CI 里。

### 线协议兼容性

验证方式：用 Rust 二进制与官方 `frp_0.71.0` 发行包在回环上对跑，一个当服务端、一个当客户端。
矩阵由 `tests/interop/interop.py` 执行。下表来自 CI（Linux）与 Windows 上的本地运行，
两端分别为本仓库构建的产物与上游 v0.71.0。

| 服务端 | 客户端 | tcp | udp | http 虚拟主机 | `useEncryption` + `useCompression` | 256 KiB 大包 |
|---|---|---|---|---|---|---|
| rust-frps | frpc 0.71.0 | ok | ok | ok | ok | ok |
| frps 0.71.0 | rust-frpc | ok | ok | ok | ok | ok |
| frps 0.71.0 | rust-frpc（`transport.tls.enable`） | ok | ok | ok | ok | ok |
| rust-frps | rust-frpc | ok | ok | ok | ok | ok |
| frps 0.71.0 | frpc 0.71.0（对照） | ok | ok | ok | ok | ok |

`stcp`：由一个实现提供代理、另一个实现发起访问，双向、两种服务端都覆盖 —— 全部通过
（协议矩阵合计 **50/50**）。

客户端插件（`tests/interop/plugins.py`）：同样四组组合，每组 27 项检查，全部通过
（合计 **141/141**）。场景包括 `http2http`、`http2https`、`https2http`、`https2https`、`tls2raw`、
`static_file`（带/不带凭据）、`socks5`、`http_proxy`（带/不带凭据），以及 `https2http` 的
`https` 虚拟主机用法。除了「能用」，它们还钉死了这些细节：

- `http2http` 会丢掉入站的 `X-Forwarded-*`：`httputil.ReverseProxy` 在调用 `Rewrite` 之前
  就把它们删了，而这个 rewrite 不会补回来；`http2https` 则逐条 copy 回来。这个不对称是上游行为，
  不是疏忽。
- `https2http` 与 `https2https` 会把客户端地址追加到 `X-Forwarded-For` 之后，并设置
  `X-Forwarded-Host`/`-Proto`；客户端地址取自服务端在 `StartWorkConn` 里报的 `src_addr`。
- 两者都会对 SNI 与 Host 不匹配的请求返回 `421`。
- `static_file` 对 `HEAD` 返回 `405` 而不是 `200`：路由是用 `Methods("GET")` 注册的。
- `http_proxy` 对未鉴权请求返回 `407`，同时支持绝对形式请求与 `CONNECT`。

覆盖到的部分：帧格式、token 签名、AES-128-CFB 控制流、yamux 双向多路复用、`0x17` TLS 双向协商、
work 连接握手、work 连接加密与 snappy framed 流、visitor 签名与基于 secretKey 的载荷加密、
`http` 虚拟主机路由，以及上述插件行为。

尚未覆盖：`xtcp` 与 `sudp` visitor、`tcpmux`、代理组、带宽限制，以及
`websocket` / `wss` / `kcp` / `quic` 传输 —— 这些均未实现。

### 路线图

- [x] **M1 — 协议核心**：消息模型、分帧、token 认证、AES-128-CFB 加密、Snappy 分帧、
      异步流适配、离线自测。
- [ ] **M2 — frps**
  - [x] 具备 TLS 感知的控制监听（自定义 `0x17` 首字节）、token 认证、run-id 顶替、
        心跳监管、work 连接池、`NewProxy` / `CloseProxy`；
  - [x] `tcp`、`udp`、`stcp`、`sudp` 代理，带 `allowPorts` 的端口管理；
  - [x] `stcp` / `sudp` 的 visitor 准入；
  - [x] `vhostHTTPPort` / `vhostHTTPSPort` 上的 `http` / `https` 虚拟主机路由：HTTP 在服务端
        终结并以 work 连接回放（Host 重写、`X-Forwarded-For`、请求/响应头策略、basic auth、
        `CONNECT` 隧道、自定义 404）；HTTPS 依据 peek 到的 ClientHello 的 SNI 路由，
        并把仍未解密的流原样转发，让 TLS 在后端端到端终结；
  - [x] 面板、JSON 管理 API、Prometheus 端点；
  - [ ] `tcpmux`、`xtcp` NAT 打洞、代理组、带宽限制。
- [x] **M3 — frpc**
  - [x] 配置加载（TOML/YAML/JSON + `includes`、`start` 白名单、重名拒绝）；
  - [x] 连接器：可选 TLS 的 TCP（自定义 `0x17` 首字节），以及 `transport.tcpMux` 默认在两端
        装上的 yamux 会话；
  - [x] 控制会话：登录、加密控制流、心跳、`NewProxy` 注册、
        `ReqWorkConn` → `NewWorkConn` → `StartWorkConn`；
  - [x] `tcp`、`http`、`https`、`stcp`、`tcpmux` 代理（走通用 TCP 路径），
        `udp` 与 `sudp`（走带帧的 UDP work 连接）；
  - [x] `stcp` visitor；
  - [x] 本地服务健康检查与注册/摘除循环；
  - [x] 指数退避重连与 run-id 复用；
  - [x] `frpc --verify`；
  - [x] 与官方 frp `v0.71.0` 发行包双向验证通过，覆盖 `useEncryption`/`useCompression`、
        任意一侧开启 TLS，以及由一个实现提供、另一个实现访问的 `stcp` 代理；
  - [x] 代理插件：`unix_domain_socket`、`static_file`、`socks5`、`http_proxy`、`http2http`、
        `http2https`、`https2http`、`https2https`、`tls2raw`；
  - [x] 插件行为通过 `tests/interop/plugins.py` 与官方发行包对照验证：十一个场景 × 四组组合，
        逐一与实时基线比对；
  - [ ] `xtcp` 与 `sudp` visitor、`virtual_net` 插件、客户端 Admin UI 与 Store、
        客户端侧带宽限制、proxy protocol 头，以及 `websocket` / `wss` / `kcp` / `quic` 传输。
- [ ] **M4 — Store**：客户端 Admin UI 与持久化代理配置。
- [ ] **M5 — 扩展传输**：KCP、QUIC、线协议 v2（AEAD 握手）、OIDC 认证、SSH 隧道网关。

### 插件

插件会取代代理的本地服务：不再拨号 `localIP:localPort`，而是把每条 work 连接交给插件处理。

| 插件 | 面向远端说什么 | 后端 |
|---|---|---|
| `unix_domain_socket` | 由该 socket 决定 | 一个 unix socket |
| `static_file` | HTTP（文件来自 `localPath`） | 无 |
| `socks5` | SOCKS5，仅 `CONNECT` | 请求中指定的主机 |
| `http_proxy` | HTTP 代理，`CONNECT` 与绝对形式 | 请求中指定的主机 |
| `http2http` | HTTP | `localAddr` 上的 HTTP |
| `http2https` | HTTP | `localAddr` 上的 HTTPS |
| `https2http` | HTTPS（`crtPath`/`keyPath`） | `localAddr` 上的 HTTP |
| `https2https` | HTTPS | `localAddr` 上的 HTTPS |
| `tls2raw` | TLS | `localAddr` 上的明文 |

```toml
# frpc.toml
[[proxies]]
name = "web"
type = "https"
customDomains = ["web.example.com"]

[proxies.plugin]
type = "https2http"
localAddr = "127.0.0.1:8080"
crtPath = "server.crt"
keyPath = "server.key"
```

与上游的差异都落在响应格式而非协议上：`static_file` 不做 gzip，目录列表使用自己的标记；
有限范围请求只支持单个 range（多 range 请求会拿到整个实体）；`virtual_net` 未实现，
配置里写它会在加载阶段被拒绝并报出插件名。

`https2http` 与 `https2https` 会终结 TLS，因此也复刻了上游那道「请求被误导」的校验：
对端发过 SNI 且与 Host 不匹配时返回 `421` 而不是照常服务。比较逻辑是一份
`pkg/util/http.CanonicalHost` 的移植，连「无法解析的主机规范化成空串」这一细节都对齐了 ——
正是这个空串会关闭校验，所以判空的先后顺序是有讲究的。

CI 既让 Rust 两端互相对跑，也与真实 frp 发行包对跑 —— 当两端都是我们自己时，
这是唯一能抓到回归的办法。见上文「测试」。

### 许可与致谢

以 Apache License 2.0 授权，与上游 frp 一致。

frp 的版权归 frp Authors 所有，以 Apache-2.0 授权。Rust-Frp 是一个独立重实现；
凡为兼容而复刻行为之处，均在模块文档中注明了对应的上游源码。

---

<a id="english"></a>

## English

**[简体中文](#简体中文) ｜ English**

A Rust reimplementation of [frp](https://github.com/fatedier/frp) — a fast reverse proxy
that exposes services behind NAT or a firewall to the public internet.

**Compatibility target: frp `v0.71.0`.** Rust-Frp is written to be *wire compatible*
with the reference Go implementation, so a Rust `frpc` can talk to an upstream `frps`
and vice versa.

> Status: **milestones 1 (protocol core), 2 (frps) and 3 (frpc) are complete**; M4
> (client store and admin UI) and M5 (extended transports) have not started. See
> [Roadmap](#roadmap).

### Wire protocol reference

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
| TLS | custom first byte `0x17` distinguishes frp TLS from real TLS (`0x16`) | `frp_core::transport`, `frp_core::tls_sni` |
| TCP multiplexing | yamux, installed by `transport.tcpMux` on both peers by default | `frp_core::yamux` |
| Virtual host routing | by `Host`/location and by SNI, with a `*` catch-all | `frp_core::vhost` |

One constant is worth calling out because it is so easy to get wrong: `golib/crypto`
ships `DefaultSalt = "crypto"`, but frp overwrites it with `"frp"` in its own `init()`.
Copying golib gives a key derivation that is self-consistent and incompatible with the
reference — the two Rust peers talk to each other happily and both fail against frp,
always just after the plaintext `Login`.

### Repository layout

```
crates/
  frp-core    protocol framing, message model, crypto, shared helpers
  frp-server  frps: listener, control session, port manager, proxy managers, admin API
  frp-client  frpc: connector, control session, proxies, visitors, plugins, admin UI
  frp-cli     rust-frp binary hosting the frps / frpc subcommands
```

### Building

```bash
cargo build --release          # produces target/release/rust-frp
cargo test --workspace         # protocol, crypto and framing unit tests
./target/release/rust-frp info # wire compatibility summary
./target/release/rust-frp selftest
```

CI (`.github/workflows/ci.yml`) runs `cargo check`, the test suite, clippy, a release
build matrix for Linux, Windows and macOS, and two further jobs: the end-to-end run and
the differential run against a real frp release.

### Running the server

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

### Running the client

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

### Testing

```bash
cargo test --workspace          # unit tests
cargo clippy --workspace --all-targets

cargo build --release
python3 tests/e2e/e2e.py        # defaults to target/release/rust-frp

# Differential checks against an upstream frp release of the same version.
python3 tests/interop/interop.py \
    --rust target/release/rust-frp \
    --upstream /path/to/frp_0.71.0_linux_amd64 \
    --with-visitors
python3 tests/interop/plugins.py \
    --rust target/release/rust-frp \
    --upstream /path/to/frp_0.71.0_linux_amd64
```

The unit tests cover the protocol layer, the crypto streams, the routers and
each component in isolation. They cannot catch a mismatch between the two
peers — a wrong assumption shared by a test and its implementation passes both
— so `tests/e2e/e2e.py` runs the built binary against itself and checks real
traffic through the tunnel: `tcp`, `udp` and an `http` virtual host over a yamux
session, the same with `tcpMux` off, TLS on the control port, and an `stcp`
visitor tunnelling to another client's proxy.

Neither of those can catch a mistake *both* peers make, which is why there is a
third layer. `tests/interop/interop.py` runs the wire protocol against a real
frp release in all four combinations (Rust↔upstream in both directions, plus
Rust↔Rust and upstream↔upstream as controls). `tests/interop/plugins.py` does
the same for the client plugins: eleven scenarios, each registered once per
implementation, each probed identically, with every observable result compared
against a live `frps`+`frpc` baseline rather than against a value written down
here.

That last part is not decoration. The misdirected-request check the
TLS-terminating plugins perform was missing here; without it, a request whose
SNI did not match its Host was served instead of refused, and nothing in the
unit or e2e suites noticed. Earlier, the AES key salt was wrong for a whole
milestone — 170 unit tests and 13 end-to-end checks passed, because both sides
were wrong in the same way. Both are in CI now.

### Wire compatibility

Verified by running the Rust binary against the official `frp_0.71.0` release,
one as the server and one as the client, over loopback. `tests/interop/interop.py`
runs the matrix; the results below come from CI on Linux and from a run on
Windows, with our binary built from this repository and the other side upstream
v0.71.0.

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

Client plugins, from `tests/interop/plugins.py`, the same four pairs and 27
checks each: ok (141/141 in total). The scenarios are `http2http`, `http2https`,
`https2http`, `https2https`, `tls2raw`, `static_file` (plain and with
credentials), `socks5`, `http_proxy` (plain and with credentials), and the
`https` vhost shape of `https2http`. What they pin down beyond "it works":

- `http2http` drops the inbound `X-Forwarded-*`, because `httputil.ReverseProxy`
  removes them before `Rewrite` runs and this rewrite does not put them back;
  `http2https` copies them back verbatim. That asymmetry is upstream's, not an
  oversight.
- `https2http` and `https2https` append the client address to `X-Forwarded-For`
  and set `X-Forwarded-Host`/`-Proto`, taking the address from the `src_addr`
  the server reported in `StartWorkConn`.
- both refuse a request whose SNI does not match its Host with `421`.
- `static_file` answers `405` for `HEAD`, not `200`: the route is registered
  with `Methods("GET")`.
- `http_proxy` answers `407` for an unauthenticated request and accepts both
  absolute-form and `CONNECT`.

What that covers: the frame format, the token signature, the AES-128-CFB
control stream, yamux multiplexing in both roles, the `0x17` TLS negotiation in
both directions, the work-connection handshake, the work-connection cipher and
the snappy framed stream, the visitor signature and the secret-key-based
visitor payload encryption, `http` virtual host routing, and the plugin
behaviour above.

Not covered yet: `xtcp` and `sudp` visitors, `tcpmux`, proxy groups, bandwidth
limiting, and the `websocket` / `wss` / `kcp` / `quic` transports, none of which
are implemented.

### Roadmap

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
  - [x] proxy plugins: `unix_domain_socket`, `static_file`, `socks5`,
        `http_proxy`, `http2http`, `http2https`, `https2http`, `https2https`,
        `tls2raw`;
  - [x] plugin behaviour verified against the official release with
        `tests/interop/plugins.py`, which runs eleven scenarios against four
        pairs of binaries and compares each to a live baseline;
  - [ ] `xtcp` and `sudp` visitors, the `virtual_net` plugin, client admin UI
        and store, client side bandwidth limiting, the proxy protocol header,
        and the `websocket` / `wss` / `kcp` / `quic` transports.
- [ ] **M4 — store**: client admin UI and persistent proxy store.
- [ ] **M5 — extended transports**: KCP, QUIC, wire protocol v2 (AEAD
      handshake), OIDC auth, SSH tunnel gateway.

### Plugins

A plugin replaces a proxy's local service: instead of dialing
`localIP:localPort`, the proxy hands every work connection to the plugin.

| plugin | what it speaks to the remote peer | backend |
|---|---|---|
| `unix_domain_socket` | whatever the socket speaks | a unix socket |
| `static_file` | HTTP (files from `localPath`) | none |
| `socks5` | SOCKS5, `CONNECT` only | the named host |
| `http_proxy` | HTTP proxy, `CONNECT` and absolute-form | the named host |
| `http2http` | HTTP | HTTP on `localAddr` |
| `http2https` | HTTP | HTTPS on `localAddr` |
| `https2http` | HTTPS (`crtPath`/`keyPath`) | HTTP on `localAddr` |
| `https2https` | HTTPS | HTTPS on `localAddr` |
| `tls2raw` | TLS | plaintext on `localAddr` |

```toml
# frpc.toml
[[proxies]]
name = "web"
type = "https"
customDomains = ["web.example.com"]

[proxies.plugin]
type = "https2http"
localAddr = "127.0.0.1:8080"
crtPath = "server.crt"
keyPath = "server.key"
```

Differences from upstream, all response-formatting rather than protocol:
`static_file` does not gzip and its directory listing is its own markup; the
finite-range support covers a single range (a multi-range request gets the whole
entity); and `virtual_net` is not implemented, so a configuration naming it is
rejected at load with the plugin's name.

`https2http` and `https2https` terminate TLS, so they also reproduce upstream's
misdirected-request guard: a request whose SNI was sent but does not match its
Host is refused with `421` rather than served. The comparison runs through a
port of `pkg/util/http.CanonicalHost`, down to the empty result an unparsable
host canonicalises to — that empty string is what disables the check, so the
order of the tests matters.

CI runs the Rust peers against each other, and against a real frp release, which
is the only way to catch a regression where both sides are ours. See
**Testing** above.

### License and attribution

Licensed under the Apache License, Version 2.0, matching upstream frp.

frp is Copyright the frp Authors and licensed under Apache-2.0. Rust-Frp is an
independent reimplementation; where behaviour is reproduced for compatibility the
corresponding upstream source is cited in module documentation.
