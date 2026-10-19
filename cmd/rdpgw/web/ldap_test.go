package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

const (
	testUserDNTemplate = "uid={username},ou=people,dc=example,dc=com"
	testGroupRDP       = "cn=rdp,ou=groups,dc=example,dc=com"
)

type testLDAPUser struct {
	password string
	memberOf []string
}

// testLDAPServer is an in-process LDAP server. Like lldap, it lets a bound
// user read only their own entry.
type testLDAPServer struct {
	addr   string
	caFile string
	binds  atomic.Int32

	mu    sync.Mutex
	users map[string]testLDAPUser // keyed by lowercased DN
	bound map[int]string          // connection id -> bound DN
}

type testLDAPMode int

const (
	modePlain testLDAPMode = iota
	modeLDAPS
)

func startTestLDAP(t *testing.T, mode testLDAPMode) *testLDAPServer {
	t.Helper()
	serverTLS, caFile := testTLSConfig(t)
	s := &testLDAPServer{
		caFile: caFile,
		users: map[string]testLDAPUser{
			"uid=alice,ou=people,dc=example,dc=com": {password: "alice-pw", memberOf: []string{"cn=other,ou=groups,dc=example,dc=com", "CN=RDP,OU=groups,DC=example,DC=com"}},
			"uid=bob,ou=people,dc=example,dc=com":   {password: "bob-pw", memberOf: []string{"cn=other,ou=groups,dc=example,dc=com"}},
		},
		bound: map[int]string{},
	}

	srv, err := gldap.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatal(err)
	}
	mux.Bind(s.handleBind)
	mux.Search(s.handleSearch)
	mux.ExtendedOperation(func(w *gldap.ResponseWriter, r *gldap.Request) {
		res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
		res.SetResponseName(gldap.ExtendedOperationStartTLS)
		w.Write(res)
		r.StartTLS(serverTLS)
	}, gldap.ExtendedOperationStartTLS)
	srv.Router(mux)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = l.Addr().String()
	l.Close()

	var opts []gldap.Option
	if mode == modeLDAPS {
		opts = append(opts, gldap.WithTLSConfig(serverTLS))
	}
	go srv.Run(s.addr, opts...)
	t.Cleanup(func() { srv.Stop() })
	for !srv.Ready() {
		time.Sleep(time.Millisecond)
	}
	return s
}

func (s *testLDAPServer) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer w.Write(resp)
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	s.binds.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(m.UserName)]
	if ok && string(m.Password) == u.password {
		s.bound[r.ConnectionID()] = strings.ToLower(m.UserName)
		resp.SetResultCode(gldap.ResultSuccess)
	}
}

func (s *testLDAPServer) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
	defer w.Write(done)
	m, err := r.GetSearchMessage()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	base := strings.ToLower(m.BaseDN)
	u, ok := s.users[base]
	if !ok || m.Scope != gldap.BaseObject || s.bound[r.ConnectionID()] != base {
		return
	}
	w.Write(r.NewSearchResponseEntry(m.BaseDN, gldap.WithAttributes(map[string][]string{"memberOf": u.memberOf})))
	done.SetResultCode(gldap.ResultSuccess)
}

// testTLSConfig returns a server config for 127.0.0.1 and the path of a
// PEM file holding its self-signed certificate.
func testTLSConfig(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, caFile
}

func newTestLDAPAuthenticator(t *testing.T, c LDAPConfig) *LDAPAuthenticator {
	t.Helper()
	if c.UserDNTemplate == "" {
		c.UserDNTemplate = testUserDNTemplate
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	a, err := NewLDAPAuthenticator(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLDAPAuthenticate(t *testing.T) {
	s := startTestLDAP(t, modePlain)
	a := newTestLDAPAuthenticator(t, LDAPConfig{URL: "ldap://" + s.addr, RequiredGroups: []string{testGroupRDP}})

	cases := []struct {
		name, user, password string
		want                 bool
		wantBind             bool
		wantErr              error
	}{
		{"member of required group", "alice", "alice-pw", true, true, nil},
		{"username case does not matter to the server", "Alice", "alice-pw", true, true, nil},
		{"wrong password", "alice", "nope", false, true, nil},
		{"unknown user", "mallory", "alice-pw", false, true, nil},
		{"not in required group", "bob", "bob-pw", false, true, ErrAccessDenied},
		{"empty password is never sent", "alice", "", false, false, nil},
		{"dn injection is rejected", "alice,ou=people", "alice-pw", false, false, nil},
		{"filter characters are rejected", "al*", "alice-pw", false, false, nil},
		{"overlong username is rejected", strings.Repeat("a", 65), "x", false, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := s.binds.Load()
			got, err := a.Authenticate(context.Background(), tc.user, tc.password)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Authenticate(%q) = %t, want %t", tc.user, got, tc.want)
			}
			if bound := s.binds.Load() != before; bound != tc.wantBind {
				t.Errorf("bind attempted = %t, want %t", bound, tc.wantBind)
			}
		})
	}
}

func TestLDAPAuthenticateWithoutRequiredGroups(t *testing.T) {
	s := startTestLDAP(t, modePlain)
	a := newTestLDAPAuthenticator(t, LDAPConfig{URL: "ldap://" + s.addr})
	if ok, err := a.Authenticate(context.Background(), "bob", "bob-pw"); err != nil || !ok {
		t.Fatalf("got (%t, %v), want (true, nil)", ok, err)
	}
}

func TestLDAPAuthenticateTLS(t *testing.T) {
	plain := startTestLDAP(t, modePlain)
	ldaps := startTestLDAP(t, modeLDAPS)

	cases := []struct {
		name string
		cfg  LDAPConfig
	}{
		{"starttls", LDAPConfig{URL: "ldap://" + plain.addr, StartTLS: true, CAFile: plain.caFile}},
		{"ldaps", LDAPConfig{URL: "ldaps://" + ldaps.addr, CAFile: ldaps.caFile}},
		{"ldaps, upper-case scheme", LDAPConfig{URL: "LDAPS://" + ldaps.addr, CAFile: ldaps.caFile}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.RequiredGroups = []string{testGroupRDP}
			a := newTestLDAPAuthenticator(t, tc.cfg)
			if !a.Encrypted() {
				t.Error("Encrypted() = false")
			}
			if ok, err := a.Authenticate(context.Background(), "alice", "alice-pw"); err != nil || !ok {
				t.Fatalf("got (%t, %v), want (true, nil)", ok, err)
			}
		})
	}

	for _, cfg := range []LDAPConfig{
		{URL: "ldap://" + plain.addr, StartTLS: true},
		{URL: "ldaps://" + ldaps.addr},
	} {
		t.Run("untrusted certificate "+cfg.URL, func(t *testing.T) {
			a := newTestLDAPAuthenticator(t, cfg)
			if _, err := a.Authenticate(context.Background(), "alice", "alice-pw"); err == nil {
				t.Fatal("expected a certificate error")
			}
		})
	}
}

func TestLDAPAuthenticateServerDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	a := newTestLDAPAuthenticator(t, LDAPConfig{URL: "ldap://" + addr, Timeout: time.Second})
	if ok, err := a.Authenticate(context.Background(), "alice", "alice-pw"); err == nil || ok {
		t.Fatalf("got (%t, %v), want an error", ok, err)
	}
}

func TestNewLDAPAuthenticatorValidation(t *testing.T) {
	valid := LDAPConfig{URL: "ldap://ldap.example.com:389", UserDNTemplate: testUserDNTemplate, Timeout: time.Second}
	cases := []struct {
		name   string
		modify func(*LDAPConfig)
	}{
		{"unsupported scheme", func(c *LDAPConfig) { c.URL = "http://ldap.example.com" }},
		{"no host", func(c *LDAPConfig) { c.URL = "ldap://" }},
		{"starttls on ldaps", func(c *LDAPConfig) { c.URL = "ldaps://ldap.example.com"; c.StartTLS = true }},
		{"template without placeholder", func(c *LDAPConfig) { c.UserDNTemplate = "uid=alice,dc=example,dc=com" }},
		{"template with two placeholders", func(c *LDAPConfig) { c.UserDNTemplate = "uid={username},cn={username},dc=example" }},
		{"template not a dn", func(c *LDAPConfig) { c.UserDNTemplate = "{username}" }},
		{"bad group dn", func(c *LDAPConfig) { c.RequiredGroups = []string{"not a dn"} }},
		{"missing ca file", func(c *LDAPConfig) { c.CAFile = filepath.Join(t.TempDir(), "missing.pem") }},
		{"zero timeout", func(c *LDAPConfig) { c.Timeout = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.modify(&c)
			if _, err := NewLDAPAuthenticator(c); err == nil {
				t.Errorf("expected an error for %+v", c)
			}
		})
	}

	if _, err := NewLDAPAuthenticator(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestLDAPAuthenticateExternal runs against a real directory, e.g. lldap:
//
//	RDPGW_TEST_LDAP_URL=ldap://localhost:3890
//	RDPGW_TEST_LDAP_USER_DN_TEMPLATE=uid={username},ou=people,dc=example,dc=com
//	RDPGW_TEST_LDAP_GROUP=cn=rdp,ou=groups,dc=example,dc=com
//	RDPGW_TEST_LDAP_MEMBER=alice:password   (in the group)
//	RDPGW_TEST_LDAP_NON_MEMBER=bob:password (not in the group)
func TestLDAPAuthenticateExternal(t *testing.T) {
	url := os.Getenv("RDPGW_TEST_LDAP_URL")
	if url == "" {
		t.Skip("RDPGW_TEST_LDAP_URL not set")
	}
	a := newTestLDAPAuthenticator(t, LDAPConfig{
		URL:            url,
		UserDNTemplate: os.Getenv("RDPGW_TEST_LDAP_USER_DN_TEMPLATE"),
		RequiredGroups: []string{os.Getenv("RDPGW_TEST_LDAP_GROUP")},
	})
	check := func(env string, want bool, wantErr error) {
		user, password, _ := strings.Cut(os.Getenv(env), ":")
		got, err := a.Authenticate(context.Background(), user, password)
		if !errors.Is(err, wantErr) || got != want {
			t.Errorf("%s: got (%t, %v), want (%t, %v)", env, got, err, want, wantErr)
		}
		if got, err := a.Authenticate(context.Background(), user, password+"x"); err != nil || got {
			t.Errorf("%s with wrong password: got (%t, %v), want (false, nil)", env, got, err)
		}
	}
	check("RDPGW_TEST_LDAP_MEMBER", true, nil)
	check("RDPGW_TEST_LDAP_NON_MEMBER", false, ErrAccessDenied)
	fmt.Println("external ldap checks ran against", url)
}

func TestBindRefused(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad")), true},
		{ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("locked")), true},
		{ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("policy")), true},
		{ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")), false},
		{ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down")), false},
		{ldap.NewError(ldap.ErrorNetwork, errors.New("reset")), false},
		{errors.New("not an ldap error"), false},
	}
	for _, tc := range cases {
		if got := bindRefused(tc.err); got != tc.want {
			t.Errorf("bindRefused(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}
