package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/web"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// These tests run the real router (registerGateway, EnrichContext, the Basic
// handler and the security checks) and speak MS-TSGU to it.

const (
	testSigningKey = "0123456789abcdef0123456789abcdef"
	ipA            = "203.0.113.10"
	ipB            = "203.0.113.20"
	basicAuthHdr   = "Basic YWxpY2U6c2VjcmV0" // alice:secret
	wrongAuthHdr   = "Basic YWxpY2U6d3Jvbmc=" // alice:wrong
	deniedHost     = "127.0.0.1:1"
)

type fakePasswords map[string]string

func (f fakePasswords) Authenticate(_ context.Context, user, pass string) (bool, error) {
	want, ok := f[user]
	return ok && want == pass, nil
}

type testEnv struct {
	srv          *httptest.Server
	addr         string
	hostA, hostB string
}

var connCounter atomic.Int64

func holdListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		for _, c := range conns {
			c.Close()
		}
	})
	return l.Addr().String()
}

// newTestEnv serves conf with a fake password backend and two allowed hosts.
func newTestEnv(t *testing.T, conf config.Configuration) *testEnv {
	t.Helper()
	oldKey, oldHosts, oldSel, oldVerify := security.SigningKey, security.Hosts, security.HostSelection, security.VerifyClientIP
	t.Cleanup(func() {
		security.SigningKey, security.Hosts, security.HostSelection, security.VerifyClientIP = oldKey, oldHosts, oldSel, oldVerify
		web.InitTrustedProxies(nil)
	})

	e := &testEnv{hostA: holdListener(t), hostB: holdListener(t)}
	security.SigningKey = []byte(testSigningKey)
	security.Hosts = []string{e.hostA, e.hostB}
	security.HostSelection = "unsigned"
	security.VerifyClientIP = true
	web.InitStore([]byte(testSigningKey), []byte(testSigningKey), "cookie", 0)
	web.InitTrustedProxies([]string{"127.0.0.0/8"})

	gw, gwBasic := newGateways(&conf)
	var basic *web.BasicAuthHandler
	if conf.Server.BasicAuthEnabled() {
		basic = &web.BasicAuthHandler{Authenticator: fakePasswords{"alice": "secret"}}
	}
	r := mux.NewRouter()
	r.Use(web.EnrichContext)
	registerGateway(r.PathPrefix(gatewayEndPoint).Subrouter(), &conf, gw, gwBasic, basic)

	// gorilla's dialer can only send GET; the protocol uses RDG_OUT_DATA.
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			req.Method = protocol.MethodRDGOUT
		}
		r.ServeHTTP(w, req)
	}))
	t.Cleanup(e.srv.Close)
	e.addr = strings.TrimPrefix(e.srv.URL, "http://")
	return e
}

func stackedConf(mode string) config.Configuration {
	return config.Configuration{
		Server: config.ServerConfig{Authentication: []string{"openid", "local"}, UnauthenticatedRequests: mode, HostSelection: "unsigned"},
		Caps:   config.RDGCapsConfig{TokenAuth: true},
	}
}

func (e *testEnv) token(t *testing.T, ip, host string) string {
	t.Helper()
	id := identity.NewUser()
	id.SetAttribute(identity.AttrClientIp, ip)
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)
	tok, err := security.GeneratePAAToken(ctx, "alice", host)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *testEnv) headers(ip, authorization string) http.Header {
	h := http.Header{}
	h.Set("X-Forwarded-For", ip)
	h.Set("Rdg-Connection-Id", fmt.Sprintf("conn-%d", connCounter.Add(1)))
	if authorization != "" {
		h.Set("Authorization", authorization)
	}
	return h
}

// --- MS-TSGU client ---

type pktIO interface {
	send(pkt []byte) error
	recv() (typ uint16, body []byte, err error)
}

type wsIO struct{ c *websocket.Conn }

func (w wsIO) send(pkt []byte) error { return w.c.WriteMessage(websocket.BinaryMessage, pkt) }
func (w wsIO) recv() (uint16, []byte, error) {
	w.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := w.c.ReadMessage()
	if err != nil {
		return 0, nil, err
	}
	return splitPacket(msg)
}

func splitPacket(msg []byte) (uint16, []byte, error) {
	if len(msg) < 8 {
		return 0, nil, fmt.Errorf("short packet")
	}
	return binary.LittleEndian.Uint16(msg), msg[8:], nil
}

func packet(typ uint16, body []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, typ)
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint32(len(body)+8))
	b.Write(body)
	return b.Bytes()
}

func u16le(s string) []byte {
	var b bytes.Buffer
	for _, c := range s {
		binary.Write(&b, binary.LittleEndian, uint16(c))
	}
	return b.Bytes()
}

func handshakeReq(caps uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0})
	binary.Write(&b, binary.LittleEndian, caps)
	return packet(protocol.PKT_TYPE_HANDSHAKE_REQUEST, b.Bytes())
}

func tunnelCreateReq(cookie string) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(protocol.HTTP_CAPABILITY_IDLE_TIMEOUT))
	fields := uint16(0)
	if cookie != "" {
		fields = protocol.HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE
	}
	binary.Write(&b, binary.LittleEndian, fields)
	binary.Write(&b, binary.LittleEndian, uint16(0))
	if cookie != "" {
		c := u16le(cookie)
		binary.Write(&b, binary.LittleEndian, uint16(len(c)))
		b.Write(c)
	}
	return packet(protocol.PKT_TYPE_TUNNEL_CREATE, b.Bytes())
}

func tunnelAuthReq(name string) []byte {
	var b bytes.Buffer
	n := u16le(name)
	binary.Write(&b, binary.LittleEndian, uint16(len(n)))
	b.Write(n)
	return packet(protocol.PKT_TYPE_TUNNEL_AUTH, b.Bytes())
}

func channelCreateReq(hostport string) []byte {
	host, port, _ := net.SplitHostPort(hostport)
	var p uint16
	fmt.Sscanf(port, "%d", &p)
	var b bytes.Buffer
	b.Write([]byte{1, 0})
	binary.Write(&b, binary.LittleEndian, p)
	binary.Write(&b, binary.LittleEndian, uint16(3))
	n := u16le(host)
	binary.Write(&b, binary.LittleEndian, uint16(len(n)))
	b.Write(n)
	return packet(protocol.PKT_TYPE_CHANNEL_CREATE, b.Bytes())
}

type outcome struct {
	stage string // last stage that succeeded: "", handshake, tunnel, auth, channel
	code  uint32 // error code of the failing response
	err   error  // transport error instead of a response
}

// run drives the gateway handshake up to channel creation.
func run(io pktIO, caps uint16, cookie, host string) outcome {
	steps := []struct {
		name    string
		req     []byte
		want    uint16
		codeOff int
	}{
		{"handshake", handshakeReq(caps), protocol.PKT_TYPE_HANDSHAKE_RESPONSE, 0},
		{"tunnel", tunnelCreateReq(cookie), protocol.PKT_TYPE_TUNNEL_RESPONSE, 2},
		{"auth", tunnelAuthReq("client"), protocol.PKT_TYPE_TUNNEL_AUTH_RESPONSE, 0},
		{"channel", channelCreateReq(host), protocol.PKT_TYPE_CHANNEL_RESPONSE, 0},
	}
	o := outcome{}
	for _, s := range steps {
		if err := io.send(s.req); err != nil {
			o.err = err
			return o
		}
		typ, body, err := io.recv()
		if err != nil {
			o.err = err
			return o
		}
		if typ != s.want || len(body) < s.codeOff+4 {
			o.err = fmt.Errorf("unexpected packet type %#x at %s", typ, s.name)
			return o
		}
		if code := binary.LittleEndian.Uint32(body[s.codeOff:]); code != 0 {
			o.code = code
			return o
		}
		o.stage = s.name
	}
	return o
}

// ws opens a websocket and returns it; on a refused upgrade the response is returned.
func (e *testEnv) ws(t *testing.T, h http.Header) (pktIO, *http.Response) {
	t.Helper()
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+e.addr+gatewayEndPoint, h)
	if err != nil {
		if resp == nil {
			t.Fatalf("dial: %v", err)
		}
		resp.Body.Close()
		return nil, resp
	}
	t.Cleanup(func() { c.Close() })
	return wsIO{c}, resp
}

const paaCaps = protocol.HTTP_EXTENDED_AUTH_PAA

func (e *testEnv) wantChannel(t *testing.T, h http.Header, caps uint16, cookie, host string) {
	t.Helper()
	io, resp := e.ws(t, h)
	if io == nil {
		t.Fatalf("upgrade refused: %s", resp.Status)
	}
	if o := run(io, caps, cookie, host); o.stage != "channel" {
		t.Fatalf("expected channel creation, got %+v", o)
	}
}

// wantRejected asserts the session never gets a channel and fails with code.
// code 0 accepts any failure.
func (e *testEnv) wantRejected(t *testing.T, h http.Header, caps uint16, cookie, host string, code uint32) {
	t.Helper()
	io, resp := e.ws(t, h)
	if io == nil {
		return // refused before the gateway
	}
	_ = resp
	o := run(io, caps, cookie, host)
	if o.stage == "channel" {
		t.Fatalf("session was granted a channel")
	}
	if code != 0 && o.code != code {
		t.Fatalf("got %+v, want code %#x", o, code)
	}
}

func (e *testEnv) want401(t *testing.T, h http.Header) *http.Response {
	t.Helper()
	io, resp := e.ws(t, h)
	if io != nil {
		t.Fatalf("expected a 401, the gateway was reached")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %s, want 401", resp.Status)
	}
	return resp
}

func wantBasicChallenge(t *testing.T, resp *http.Response) {
	t.Helper()
	if got := resp.Header.Get("WWW-Authenticate"); got != web.BasicChallenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, web.BasicChallenge)
	}
}

// --- stacked ---

func TestStackedPAARejectsMissingToken(t *testing.T) {
	e := newTestEnv(t, stackedConf(""))
	// no PAA capability: capability mismatch
	e.wantRejected(t, e.headers(ipA, ""), 0, "", e.hostA, protocol.E_PROXY_CAPABILITYMISMATCH)
	// PAA capability but no cookie
	e.wantRejected(t, e.headers(ipA, ""), paaCaps, "", e.hostA, protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
}

func TestStackedPAARejectsForgedToken(t *testing.T) {
	e := newTestEnv(t, stackedConf("paa"))
	e.wantRejected(t, e.headers(ipA, ""), paaCaps, "not.a.token", e.hostA, protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)

	security.SigningKey = []byte("ffffffffffffffffffffffffffffffff")
	forged := e.token(t, ipA, e.hostA)
	security.SigningKey = []byte(testSigningKey)
	e.wantRejected(t, e.headers(ipA, ""), paaCaps, forged, e.hostA, protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
}

func TestStackedPAAValidToken(t *testing.T) {
	e := newTestEnv(t, stackedConf(""))
	e.wantChannel(t, e.headers(ipA, ""), paaCaps, e.token(t, ipA, e.hostA), e.hostA)
}

func TestStackedPAATokenBoundToClientIP(t *testing.T) {
	e := newTestEnv(t, stackedConf(""))
	tok := e.token(t, ipA, e.hostA)
	e.wantRejected(t, e.headers(ipB, ""), paaCaps, tok, e.hostA, protocol.E_PROXY_RAP_ACCESSDENIED)
}

func TestStackedPAATokenBoundToHost(t *testing.T) {
	e := newTestEnv(t, stackedConf(""))
	tok := e.token(t, ipA, e.hostA)
	e.wantRejected(t, e.headers(ipA, ""), paaCaps, tok, e.hostB, protocol.E_PROXY_RAP_ACCESSDENIED)
}

func TestStackedBasic(t *testing.T) {
	for _, mode := range []string{"paa", "challenge"} {
		t.Run(mode, func(t *testing.T) {
			e := newTestEnv(t, stackedConf(mode))

			// wrong password never reaches a gateway, whatever else the client sends
			resp := e.want401(t, e.headers(ipA, wrongAuthHdr))
			wantBasicChallenge(t, resp)
			e.want401(t, e.headers(ipA, "basic YWxpY2U6d3Jvbmc="))

			// correct password: no PAA cookie, no ext-auth caps
			e.wantChannel(t, e.headers(ipA, basicAuthHdr), 0, "", e.hostA)
			e.wantChannel(t, e.headers(ipB, basicAuthHdr), 0, "", e.hostB)
			e.wantRejected(t, e.headers(ipA, basicAuthHdr), 0, "", deniedHost, protocol.E_PROXY_RAP_ACCESSDENIED)

			// the Basic gateway does not take a PAA token
			e.wantRejected(t, e.headers(ipA, basicAuthHdr), paaCaps, e.token(t, ipA, e.hostA), e.hostA, protocol.E_PROXY_CAPABILITYMISMATCH)
		})
	}
}

func TestStackedChallenge(t *testing.T) {
	e := newTestEnv(t, stackedConf("challenge"))
	wantBasicChallenge(t, e.want401(t, e.headers(ipA, "")))
	// a PAA client that sends no Authorization never reaches the PAA path
	e.want401(t, e.headers(ipA, ""))
	e.wantChannel(t, e.headers(ipA, basicAuthHdr), 0, "", e.hostA)
}

func TestStackedOtherSchemeGoesToPAA(t *testing.T) {
	for _, mode := range []string{"paa", "challenge"} {
		t.Run(mode, func(t *testing.T) {
			e := newTestEnv(t, stackedConf(mode))
			e.wantRejected(t, e.headers(ipA, "Bearer x"), 0, "", e.hostA, protocol.E_PROXY_CAPABILITYMISMATCH)
			e.wantRejected(t, e.headers(ipA, "Bearer x"), paaCaps, "bogus", e.hostA, protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
			e.wantChannel(t, e.headers(ipA, "Bearer x"), paaCaps, e.token(t, ipA, e.hostA), e.hostA)
		})
	}
}

// --- legacy transport (RDG_OUT_DATA + RDG_IN_DATA over raw TCP) ---

type legacyIO struct {
	in  net.Conn
	out *bufio.Reader
}

func (l legacyIO) send(pkt []byte) error {
	_, err := fmt.Fprintf(l.in, "%x\r\n%s\r\n", len(pkt), pkt)
	return err
}

func (l legacyIO) recv() (uint16, []byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(l.out, hdr); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-8)
	if _, err := io.ReadFull(l.out, body); err != nil {
		return 0, nil, err
	}
	return binary.LittleEndian.Uint16(hdr), body, nil
}

func (e *testEnv) rawRequest(t *testing.T, method string, h http.Header, extra string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n%s", method, gatewayEndPoint, e.addr, extra)
	h.Write(&b)
	b.WriteString("\r\n")
	if _, err := c.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

func skipHeaders(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			return strings.TrimSpace(status)
		}
	}
}

// legacySession opens both halves. in is nil when the RDG_IN_DATA half was
// refused; its status line is returned.
func (e *testEnv) legacySession(t *testing.T, outHdr, inHdr http.Header) (pktIO, string) {
	t.Helper()
	_, outR := e.rawRequest(t, protocol.MethodRDGOUT, outHdr, "")
	if s := skipHeaders(t, outR); s != "HTTP/1.1 200 OK" {
		t.Fatalf("RDG_OUT_DATA: %s", s)
	}
	if _, err := io.ReadFull(outR, make([]byte, 10)); err != nil { // seed
		t.Fatal(err)
	}

	inC, inR := e.rawRequest(t, protocol.MethodRDGIN, inHdr, "Content-Length: 1073741824\r\n")
	status := skipHeaders(t, inR)
	if status != "HTTP/1.1 200 OK" {
		return nil, status
	}
	// The gateway discards the first read after accepting; keep it apart
	// from the first packet.
	inC.Write(bytes.Repeat([]byte{'x'}, 16))
	time.Sleep(200 * time.Millisecond)
	return legacyIO{in: inC, out: outR}, status
}

func TestStackedLegacyPAA(t *testing.T) {
	e := newTestEnv(t, stackedConf("paa"))
	id := fmt.Sprintf("legacy-%d", connCounter.Add(1))
	h := func(ip string) http.Header {
		hh := http.Header{}
		hh.Set("X-Forwarded-For", ip)
		hh.Set("Rdg-Connection-Id", id)
		return hh
	}

	// RDG_IN from another client IP must not pair with the RDG_OUT of ip A
	if io, status := e.legacySession(t, h(ipA), h(ipB)); io != nil || !strings.Contains(status, "401") {
		t.Fatalf("RDG_IN from a different IP: %q, want 401", status)
	}

	// same IP: the session works with a valid token
	id = fmt.Sprintf("legacy-%d", connCounter.Add(1))
	io, status := e.legacySession(t, h(ipA), h(ipA))
	if io == nil {
		t.Fatalf("RDG_IN from the same IP refused: %s", status)
	}
	if o := run(io, paaCaps, e.token(t, ipA, e.hostA), e.hostA); o.stage != "channel" {
		t.Fatalf("expected channel creation, got %+v", o)
	}

	// and still needs the token
	id = fmt.Sprintf("legacy-%d", connCounter.Add(1))
	io, status = e.legacySession(t, h(ipA), h(ipA))
	if io == nil {
		t.Fatalf("RDG_IN from the same IP refused: %s", status)
	}
	if o := run(io, paaCaps, "bogus", e.hostA); o.stage == "channel" || o.code != protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED {
		t.Fatalf("expected the cookie to be refused, got %+v", o)
	}
}

// --- non-stacked configurations route as before ---

func TestOpenIDOnlyRouting(t *testing.T) {
	conf := config.Configuration{
		Server: config.ServerConfig{Authentication: []string{"openid"}, HostSelection: "unsigned"},
		Caps:   config.RDGCapsConfig{TokenAuth: true},
	}
	e := newTestEnv(t, conf)
	e.wantChannel(t, e.headers(ipA, ""), paaCaps, e.token(t, ipA, e.hostA), e.hostA)
	e.wantRejected(t, e.headers(ipA, ""), paaCaps, "bogus", e.hostA, protocol.E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
	// any Authorization header reaches the same unauthenticated gateway
	e.wantChannel(t, e.headers(ipA, "Bearer x"), paaCaps, e.token(t, ipA, e.hostA), e.hostA)
}

func TestLdapOnlyRouting(t *testing.T) {
	conf := config.Configuration{
		Server: config.ServerConfig{Authentication: []string{"ldap"}, HostSelection: "unsigned"},
	}
	e := newTestEnv(t, conf)
	wantBasicChallenge(t, e.want401(t, e.headers(ipA, "")))
	wantBasicChallenge(t, e.want401(t, e.headers(ipA, wrongAuthHdr)))
	e.wantChannel(t, e.headers(ipA, basicAuthHdr), 0, "", e.hostA)
	e.wantRejected(t, e.headers(ipA, basicAuthHdr), 0, "", deniedHost, protocol.E_PROXY_RAP_ACCESSDENIED)
}
