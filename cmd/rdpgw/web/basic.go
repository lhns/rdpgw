package web

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	protocolGrpc = "unix"
)

// PasswordAuthenticator verifies a username and password. A wrong password
// is (false, nil), valid credentials without access are (false,
// ErrAccessDenied), and any other error means the backend could not answer.
type PasswordAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (bool, error)
}

var ErrAccessDenied = errors.New("user may not use the gateway")

// maxUsernameLen bounds what reaches the lockout table and the backend.
const maxUsernameLen = 256

type BasicAuthHandler struct {
	Authenticator PasswordAuthenticator
	// RequireProxyTLS accepts credentials only from a trusted proxy that
	// terminated TLS (X-Forwarded-Proto: https). Set when rdpgw serves
	// plain HTTP.
	RequireProxyTLS bool
	// IPLimiter and UserLimiter throttle attempts per client IP and per
	// (lowercased) username. Nil disables either.
	IPLimiter   *FailureLimiter
	UserLimiter *FailureLimiter
}

func (h *BasicAuthHandler) BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.RequireProxyTLS && !viaTLSProxy(r) {
			log.Printf("auth: result=rejected method=basic reason=insecure_transport remote_addr=%q", r.RemoteAddr)
			http.Error(w, "TLS required", http.StatusForbidden)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || len(username) > maxUsernameLen {
			// The client's first request carries no credentials; this
			// challenge is what makes it send them.
			basicAuthChallenge(w)
			return
		}

		id := identity.FromRequestCtx(r)
		clientIp, _ := id.GetAttribute(identity.AttrClientIp).(string)
		ipKey := ipLimiterKey(clientIp)
		userKey := strings.ToLower(username)

		if !h.acquire(h.IPLimiter, "ip", ipKey) || !h.acquire(h.UserLimiter, "user", userKey) {
			logBasicAuth("failure", "locked_out", username, clientIp)
			basicAuthChallenge(w)
			return
		}

		authenticated, err := h.Authenticator.Authenticate(r.Context(), username, password)
		if errors.Is(err, ErrAccessDenied) {
			logBasicAuth("failure", "access_denied", username, clientIp)
			basicAuthChallenge(w)
			return
		}
		if err != nil {
			// A backend outage is not the client's failure.
			h.IPLimiter.Succeeded(ipKey, false)
			h.UserLimiter.Succeeded(userKey, false)
			log.Printf("auth: result=error method=basic user=%q client_ip=%q error=%q", username, clientIp, err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if !authenticated {
			logBasicAuth("failure", "invalid_credentials", username, clientIp)
			basicAuthChallenge(w)
			return
		}

		// The IP keeps its failures: a valid account must not reset the
		// budget for guessing other accounts' passwords.
		h.IPLimiter.Succeeded(ipKey, false)
		h.UserLimiter.Succeeded(userKey, true)
		logBasicAuth("success", "", username, clientIp)

		id.SetUserName(username)
		id.SetAuthenticated(true)
		id.SetAuthTime(time.Now())
		next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
	}
}

func (h *BasicAuthHandler) acquire(l *FailureLimiter, scope, key string) bool {
	ok, lockedNow := l.Acquire(key)
	if lockedNow {
		log.Printf("auth: result=lockout method=basic scope=%s key=%q duration=%s", scope, key, l.lockout)
	}
	return ok
}

// logBasicAuth writes one key=value line per attempt for log-based
// alerting (fail2ban, Loki). Never pass it the password.
func logBasicAuth(result, reason, username, clientIp string) {
	if reason == "" {
		log.Printf("auth: result=%s method=basic user=%q client_ip=%q", result, username, clientIp)
		return
	}
	log.Printf("auth: result=%s method=basic reason=%s user=%q client_ip=%q", result, reason, username, clientIp)
}

func basicAuthChallenge(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func viaTLSProxy(r *http.Request) bool {
	if !remoteIsTrustedProxy(r.RemoteAddr) {
		return false
	}
	// The last value is the one our proxy set; earlier ones may come from
	// the client. Proxies such as Traefik report a websocket upgrade over
	// TLS as "wss".
	protos := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
	last := strings.TrimSpace(protos[len(protos)-1])
	return strings.EqualFold(last, "https") || strings.EqualFold(last, "wss")
}

// ipLimiterKey groups IPv6 clients by /64, the smallest prefix a single
// subscriber usually gets, so address rotation does not reset the count.
func ipLimiterKey(clientIp string) string {
	ip := net.ParseIP(clientIp)
	if ip == nil || ip.To4() != nil {
		return clientIp
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// SocketAuthenticator verifies credentials through rdpgw-auth (PAM) on its
// unix socket.
type SocketAuthenticator struct {
	SocketAddress string
	Timeout       int
}

func (s *SocketAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if s.SocketAddress == "" {
		return false, nil
	}

	conn, err := grpc.Dial(s.SocketAddress, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial(protocolGrpc, addr)
		}))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	c := auth.NewAuthenticateClient(conn)
	ctx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(s.Timeout))
	defer cancel()

	res, err := c.Authenticate(ctx, &auth.UserPass{Username: username, Password: password})
	if err != nil {
		return false, err
	}
	return res.Authenticated, nil
}
