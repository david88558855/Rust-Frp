// Command frpvec encodes a fixed set of control messages with upstream frp's
// own types and framing, and prints the resulting wire frames.
//
// The point is that nothing here is reimplemented. The message structs come
// from `github.com/fatedier/frp/pkg/msg` and the framing comes from
// `github.com/fatedier/golib/msg/json` — the two packages frps and frpc
// themselves use. Whatever bytes this program prints are, by construction, the
// bytes frp puts on the wire for that message.
//
// Output is newline delimited JSON, one record per case:
//
//	{"name":"login/typical","type_byte":"o","body":"{...}","frame":"6f..."}
//
// The Rust side compares its own encoding against `body`, and its own framing
// against `frame`.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"

	jsonmsg "github.com/fatedier/golib/msg/json"
	"github.com/fatedier/frp/pkg/msg"
)

// udpAddr is a shorthand for the *net.UDPAddr frp puts in UDPPacket. Note that
// encoding/json serialises net.IP as a plain string, which is why the vectors
// show "IP":"127.0.0.1" rather than a byte array.
func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// caseFn builds one message instance. Returning a pointer is required: Pack
// looks the type byte up under reflect.TypeOf(msg).Elem().
type caseFn func() any

type spec struct {
	name    string
	build   caseFn
	comment string
}

var ctl = jsonmsg.NewMsgCtl()

func init() {
	ctl.RegisterMsg(msg.TypeLogin, msg.Login{})
	ctl.RegisterMsg(msg.TypeLoginResp, msg.LoginResp{})
	ctl.RegisterMsg(msg.TypeNewProxy, msg.NewProxy{})
	ctl.RegisterMsg(msg.TypeNewProxyResp, msg.NewProxyResp{})
	ctl.RegisterMsg(msg.TypeCloseProxy, msg.CloseProxy{})
	ctl.RegisterMsg(msg.TypeNewWorkConn, msg.NewWorkConn{})
	ctl.RegisterMsg(msg.TypeReqWorkConn, msg.ReqWorkConn{})
	ctl.RegisterMsg(msg.TypeStartWorkConn, msg.StartWorkConn{})
	ctl.RegisterMsg(msg.TypeNewVisitorConn, msg.NewVisitorConn{})
	ctl.RegisterMsg(msg.TypeNewVisitorConnResp, msg.NewVisitorConnResp{})
	ctl.RegisterMsg(msg.TypePing, msg.Ping{})
	ctl.RegisterMsg(msg.TypePong, msg.Pong{})
	ctl.RegisterMsg(msg.TypeUDPPacket, msg.UDPPacket{})
	ctl.RegisterMsg(msg.TypeNatHoleVisitor, msg.NatHoleVisitor{})
	ctl.RegisterMsg(msg.TypeNatHoleClient, msg.NatHoleClient{})
	ctl.RegisterMsg(msg.TypeNatHoleResp, msg.NatHoleResp{})
	ctl.RegisterMsg(msg.TypeNatHoleSid, msg.NatHoleSid{})
	ctl.RegisterMsg(msg.TypeNatHoleReport, msg.NatHoleReport{})
}

var specs = []spec{
	{"login/zero", func() any { return &msg.Login{} },
		"Every field is omitempty, so a zero Login is {}."},
	{"login/typical", func() any {
		return &msg.Login{
			Version: "0.71.0", Hostname: "buildbox", Os: "linux", Arch: "amd64",
			User: "runner", PrivilegeKey: "f0e1d2c3", Timestamp: 1700000000,
			RunID: "abcdefghijklmnop", Metas: map[string]string{"env": "ci"},
		}
	}, "The shape frpc actually sends."},
	{"login/client_spec", func() any {
		return &msg.Login{
			Version: "0.71.0", ClientSpec: msg.ClientSpec{Type: "test", AlwaysAuthPass: true},
		}
	}, "client_spec is a struct, always present, and its own fields are omitempty."},
	{"login/unicode_metas", func() any {
		return &msg.Login{
			Version: "0.71.0",
			Metas:   map[string]string{"主机": "北京"},
		}
	}, "Go's json.Marshal escapes non ASCII by default."},
	{"login/empty_metas_map", func() any {
		return &msg.Login{Version: "0.71.0", Metas: map[string]string{}}
	}, "An empty but non nil map is omitted by omitempty, unlike a nil one seen through encode/json."},

	{"login_resp/ok", func() any {
		return &msg.LoginResp{Version: "0.71.0", RunID: "abcdefghijklmnop"}
	}, "A successful login carries an empty error string, which is omitted."},
	{"login_resp/error", func() any {
		return &msg.LoginResp{
			Error: "token in login doesn't match token from configuration",
		}
	}, "Login failure."},

	{"new_proxy/tcp", func() any {
		return &msg.NewProxy{
			ProxyName: "tcp-echo", ProxyType: "tcp", RemotePort: 38910,
		}
	}, "snake_case on the wire despite the camelCase TOML."},
	{"new_proxy/http_vhost", func() any {
		return &msg.NewProxy{
			ProxyName: "web", ProxyType: "http", CustomDomains: []string{"web.test"},
		}
	}, "subdomain is the wire key; the TOML key is subDomain."},
	{"new_proxy/encrypted_compressed", func() any {
		return &msg.NewProxy{
			ProxyName: "secure", ProxyType: "tcp", RemotePort: 38911,
			UseEncryption: true, UseCompression: true,
			BandwidthLimit: "1MB", BandwidthLimitMode: "client",
		}
	}, "Boolean flags and a bandwidth limit string."},

	{"new_proxy_resp/ok", func() any {
		return &msg.NewProxyResp{ProxyName: "tcp-echo", RemoteAddr: ":38910"}
	}, "Bare port means all interfaces."},
	{"new_proxy_resp/error", func() any {
		return &msg.NewProxyResp{ProxyName: "tcp-echo", Error: "port already used"}
	}, "Common failure."},

	{"close_proxy", func() any {
		return &msg.CloseProxy{ProxyName: "tcp-echo"}
	}, "Unregister."},

	{"new_work_conn", func() any {
		return &msg.NewWorkConn{
			RunID: "abcdefghijklmnop",
			PrivilegeKey: "1c8bfe8f801d79745c4631d09fff36c8",
			Timestamp:    1700000000,
		}
	}, "Signed with the md5 privilege key."},

	{"req_work_conn", func() any { return &msg.ReqWorkConn{} },
		"An empty struct is {}."},

	{"start_work_conn", func() any {
		return &msg.StartWorkConn{
			ProxyName: "tcp-echo", SrcAddr: "127.0.0.1", DstAddr: "192.168.1.10",
			SrcPort: 51000, DstPort: 38910,
		}
	}, "Ports are uint16."},

	{"new_visitor_conn", func() any {
		return &msg.NewVisitorConn{
			RunID: "abcdefghijklmnop", ProxyName: "secret",
			SignKey: "deadbeef", Timestamp: 1700000000,
		}
	}, "Visitor handshake."},
	{"new_visitor_conn/flags", func() any {
		return &msg.NewVisitorConn{
			RunID: "abcdefghijklmnop", ProxyName: "secret",
			SignKey: "deadbeef", Timestamp: 1700000000,
			UseEncryption: true, UseCompression: true,
		}
	}, "Per visitor data path flags."},

	{"new_visitor_conn_resp/ok", func() any {
		return &msg.NewVisitorConnResp{ProxyName: "secret"}
	}, "Accepted."},

	{"ping", func() any {
		return &msg.Ping{
			PrivilegeKey: "1c8bfe8f801d79745c4631d09fff36c8",
			Timestamp:    1700000000,
		}
	}, "Heartbeat."},
	{"pong", func() any { return &msg.Pong{} },
		"An empty Pong is {}; an error would carry text."},

	{"udp_packet/basic", func() any {
		return &msg.UDPPacket{
			Content:   []byte("hello"),
			LocalAddr: udpAddr("127.0.0.1", 53),
		}
	}, "Content is base64 in key c. Cache the exact byte layout."},
	{"udp_packet/both_addrs", func() any {
		return &msg.UDPPacket{
			Content:    []byte{0, 1, 2, 3, 4},
			LocalAddr:  udpAddr("10.0.0.2", 41234),
			RemoteAddr: udpAddr("8.8.8.8", 53),
		}
	}, "Both ends set, which is what the server echoes."},
	{"udp_packet/empty_content", func() any {
		return &msg.UDPPacket{
			LocalAddr: udpAddr("127.0.0.1", 1),
		}
	}, "A zero length datagram is legal; content is omitted when empty."},

	{"nat_hole_visitor", func() any {
		return &msg.NatHoleVisitor{
			TransactionID: "txn0000000000001", ProxyName: "p2p",
			PreCheck: true, Protocol: "quic",
			SignKey: "deadbeef", Timestamp: 1700000000,
		}
	}, "xtcp pre check."},
	{"nat_hole_client", func() any {
		return &msg.NatHoleClient{
			TransactionID: "txn0000000000001", ProxyName: "p2p",
			Sid: "0123456789abcdef",
		}
	}, "Client half of the punch."},
	{"nat_hole_resp", func() any {
		return &msg.NatHoleResp{
			TransactionID:  "txn0000000000001",
			Sid:            "0123456789abcdef",
			Protocol:       "quic",
			CandidateAddrs: []string{"1.2.3.4:6000"},
			DetectBehavior: msg.NatHoleDetectBehavior{Role: "server"},
		}
	}, "detect_behavior is nested and itself omitempty inside."},
	{"nat_hole_sid", func() any {
		return &msg.NatHoleSid{
			TransactionID: "txn0000000000001",
			Sid:           "0123456789abcdef",
			Response:      true,
			Nonce:         "nonce-value",
		}
	}, "Session id exchange."},
	{"nat_hole_report", func() any {
		return &msg.NatHoleReport{Sid: "0123456789abcdef", Success: true}
	}, "Outcome."},
}

type record struct {
	Name     string `json:"name"`
	TypeByte string `json:"type_byte"`
	Body     string `json:"body"`
	Frame    string `json:"frame"`
	Comment  string `json:"comment"`
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	for _, s := range specs {
		instance := s.build()
		frame, err := ctl.Pack(instance)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: pack: %v\n", s.name, err)
			os.Exit(1)
		}
		// The frame is typeByte || i64 BE length || body; recover the body so
		// the record carries both the payload and the whole frame.
		if len(frame) < 9 {
			fmt.Fprintf(os.Stderr, "%s: frame shorter than the header\n", s.name)
			os.Exit(1)
		}
		body := string(frame[9:])
		rec := record{
			Name:     s.name,
			TypeByte: string(frame[0]),
			Body:     body,
			Frame:    hex.EncodeToString(frame),
			Comment:  s.comment,
		}
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "%s: encode record: %v\n", s.name, err)
			os.Exit(1)
		}
	}
}
