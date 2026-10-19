package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

type fakeAuthenticator struct {
	users map[string]string
	err   error
	calls int
}

func (f *fakeAuthenticator) Authenticate(_ context.Context, username, password string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	p, ok := f.users[username]
	return ok && p == password, nil
}

type basicAuthRequest struct {
	remoteAddr, forwardedProto string
	clientIp                   string
	user, password             string
}

// serveBasicAuth runs one request through h and returns the response and
// the username the next handler saw ("" if it was not called).
func serveBasicAuth(h *BasicAuthHandler, req basicAuthRequest) (*httptest.ResponseRecorder, string) {
	var authenticatedAs string
	next := func(w http.ResponseWriter, r *http.Request) {
		authenticatedAs = identity.FromRequestCtx(r).UserName()
	}
	r := httptest.NewRequest("RDG_OUT_DATA", "/remoteDesktopGateway/", nil)
	if req.remoteAddr != "" {
		r.RemoteAddr = req.remoteAddr
	}
	if req.forwardedProto != "" {
		r.Header.Set("X-Forwarded-Proto", req.forwardedProto)
	}
	if req.user != "" {
		r.SetBasicAuth(req.user, req.password)
	}
	id := identity.NewUser()
	if req.clientIp == "" {
		req.clientIp = "198.51.100.7"
	}
	id.SetAttribute(identity.AttrClientIp, req.clientIp)
	r = identity.AddToRequestCtx(id, r)

	w := httptest.NewRecorder()
	h.BasicAuth(next)(w, r)
	return w, authenticatedAs
}

func TestBasicAuth(t *testing.T) {
	cases := []struct {
		name       string
		req        basicAuthRequest
		backendErr error
		wantCode   int
		wantUser   string
	}{
		{"valid credentials", basicAuthRequest{user: "alice", password: "pw"}, nil, http.StatusOK, "alice"},
		{"wrong password", basicAuthRequest{user: "alice", password: "nope"}, nil, http.StatusUnauthorized, ""},
		{"no credentials", basicAuthRequest{}, nil, http.StatusUnauthorized, ""},
		{"backend down", basicAuthRequest{user: "alice", password: "pw"}, errors.New("down"), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &BasicAuthHandler{Authenticator: &fakeAuthenticator{users: map[string]string{"alice": "pw"}, err: tc.backendErr}}
			w, user := serveBasicAuth(h, tc.req)
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if user != tc.wantUser {
				t.Errorf("authenticated as %q, want %q", user, tc.wantUser)
			}
			if w.Code == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without a WWW-Authenticate challenge")
			}
		})
	}
}

func TestBasicAuthRequireProxyTLS(t *testing.T) {
	InitTrustedProxies([]string{"10.0.0.0/8"})
	t.Cleanup(func() { InitTrustedProxies(nil) })

	cases := []struct {
		name     string
		req      basicAuthRequest
		wantCode int
	}{
		{"trusted proxy over https", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "https"}, http.StatusOK},
		{"trusted proxy appended https", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "http, HTTPS"}, http.StatusOK},
		{"client-supplied https before the proxy's http", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "https, http"}, http.StatusForbidden},
		{"trusted proxy over http", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "http"}, http.StatusForbidden},
		{"trusted proxy websocket over tls", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "wss"}, http.StatusOK},
		{"trusted proxy websocket in the clear", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "ws"}, http.StatusForbidden},
		{"client-supplied wss before the proxy's ws", basicAuthRequest{remoteAddr: "10.1.2.3:4000", forwardedProto: "wss, ws"}, http.StatusForbidden},
		{"trusted proxy without proto", basicAuthRequest{remoteAddr: "10.1.2.3:4000"}, http.StatusForbidden},
		{"direct client claiming https", basicAuthRequest{remoteAddr: "192.0.2.1:4000", forwardedProto: "https"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &fakeAuthenticator{users: map[string]string{"alice": "pw"}}
			h := &BasicAuthHandler{Authenticator: backend, RequireProxyTLS: true}
			tc.req.user, tc.req.password = "alice", "pw"
			w, _ := serveBasicAuth(h, tc.req)
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if tc.wantCode == http.StatusForbidden && backend.calls != 0 {
				t.Error("credentials were checked although the transport was rejected")
			}
		})
	}
}

func TestBasicAuthLockout(t *testing.T) {
	newHandler := func() (*BasicAuthHandler, *fakeAuthenticator) {
		backend := &fakeAuthenticator{users: map[string]string{"alice": "pw", "bob": "pw"}}
		return &BasicAuthHandler{
			Authenticator: backend,
			IPLimiter:     NewFailureLimiter(5, time.Minute, time.Hour),
			UserLimiter:   NewFailureLimiter(3, time.Minute, time.Hour),
		}, backend
	}
	attempt := func(h *BasicAuthHandler, ip, user, password string) int {
		w, _ := serveBasicAuth(h, basicAuthRequest{clientIp: ip, user: user, password: password})
		return w.Code
	}

	t.Run("username locked across source addresses", func(t *testing.T) {
		h, backend := newHandler()
		for i := 0; i < 3; i++ {
			attempt(h, fmt.Sprintf("192.0.2.%d", i), "alice", "guess")
		}
		calls := backend.calls
		if code := attempt(h, "192.0.2.99", "ALICE", "pw"); code != http.StatusUnauthorized {
			t.Errorf("locked user got %d, want 401", code)
		}
		if backend.calls != calls {
			t.Error("backend was asked although the user is locked out")
		}
		if code := attempt(h, "192.0.2.99", "bob", "pw"); code != http.StatusOK {
			t.Errorf("other user got %d, want 200", code)
		}
	})

	t.Run("source address locked across usernames", func(t *testing.T) {
		h, _ := newHandler()
		for i := 0; i < 5; i++ {
			attempt(h, "192.0.2.1", fmt.Sprintf("user%d", i), "guess")
		}
		if code := attempt(h, "192.0.2.1", "bob", "pw"); code != http.StatusUnauthorized {
			t.Errorf("locked address got %d, want 401", code)
		}
		if code := attempt(h, "192.0.2.2", "bob", "pw"); code != http.StatusOK {
			t.Errorf("other address got %d, want 200", code)
		}
	})

	t.Run("success clears the user's failures", func(t *testing.T) {
		h, _ := newHandler()
		for round := 0; round < 3; round++ {
			ip := fmt.Sprintf("192.0.2.%d", round)
			attempt(h, ip, "alice", "guess")
			attempt(h, ip, "alice", "guess")
			if code := attempt(h, ip, "alice", "pw"); code != http.StatusOK {
				t.Fatalf("round %d: got %d, want 200", round, code)
			}
		}
	})

	t.Run("success keeps the address's failures", func(t *testing.T) {
		h, _ := newHandler()
		for i := 0; i < 5; i++ {
			attempt(h, "192.0.2.1", fmt.Sprintf("user%d", i), "guess")
			attempt(h, "192.0.2.1", "bob", "pw")
		}
		if code := attempt(h, "192.0.2.1", "bob", "pw"); code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401: logging in to one account must not reset the guessing budget", code)
		}
	})

	t.Run("access denied counts as a failure", func(t *testing.T) {
		h, backend := newHandler()
		backend.err = ErrAccessDenied
		for i := 0; i < 3; i++ {
			if code := attempt(h, "192.0.2.1", "carol", "pw"); code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", code)
			}
		}
		calls := backend.calls
		attempt(h, "192.0.2.1", "carol", "pw")
		if backend.calls != calls {
			t.Error("backend was asked although the user is locked out")
		}
	})

	t.Run("ipv6 clients share a /64", func(t *testing.T) {
		h, _ := newHandler()
		for i := 0; i < 5; i++ {
			attempt(h, fmt.Sprintf("2001:db8:1:2::%x", i+1), fmt.Sprintf("user%d", i), "guess")
		}
		if code := attempt(h, "2001:db8:1:2:ffff::1", "bob", "pw"); code != http.StatusUnauthorized {
			t.Errorf("same /64 got %d, want 401", code)
		}
		if code := attempt(h, "2001:db8:1:3::1", "bob", "pw"); code != http.StatusOK {
			t.Errorf("other /64 got %d, want 200", code)
		}
	})

	t.Run("overlong usernames never reach the backend", func(t *testing.T) {
		h, backend := newHandler()
		if code := attempt(h, "192.0.2.1", strings.Repeat("a", maxUsernameLen+1), "pw"); code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", code)
		}
		if backend.calls != 0 || len(h.UserLimiter.entries) != 0 {
			t.Error("overlong username was checked or tracked")
		}
	})

	t.Run("backend errors do not count", func(t *testing.T) {
		h, backend := newHandler()
		backend.err = errors.New("down")
		for i := 0; i < 10; i++ {
			attempt(h, "192.0.2.1", "alice", "pw")
		}
		backend.err = nil
		if code := attempt(h, "192.0.2.1", "alice", "pw"); code != http.StatusOK {
			t.Errorf("got %d after an outage, want 200", code)
		}
	})
}
