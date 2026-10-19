package web

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/jcmturner/goidentity/v6"
)

// trustedProxyNets is the CIDR allow-list of upstream proxies whose
// X-Forwarded-For header is honored. Empty (the default) means XFF is
// ignored entirely and the client IP is taken from r.RemoteAddr.
var trustedProxyNets []*net.IPNet

// InitTrustedProxies parses the operator-supplied CIDRs once at startup.
// A bad CIDR is fatal; an empty list disables XFF-derived client-IP
// attribution.
func InitTrustedProxies(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			log.Fatalf("trustedproxies: invalid CIDR %q: %s", raw, err)
		}
		nets = append(nets, n)
	}
	trustedProxyNets = nets
}

func remoteIsTrustedProxy(remoteAddr string) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isTrustedProxyIP(ip)
}

func isTrustedProxyIP(ip net.IP) bool {
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedClient picks the client from X-Forwarded-For: the rightmost
// address not in TrustedProxies. Entries left of it were written by the
// client or by proxies we do not trust, so they are ignored. If every hop is
// trusted, the leftmost one is the client. A malformed entry ends the walk at
// the hop that appended it. proxies are the trusted hops right of the client.
func forwardedClient(headers []string, peer string) (client string, proxies []string) {
	var hops []string
	for _, h := range headers {
		for _, hop := range strings.Split(h, ",") {
			if hop = strings.TrimSpace(hop); hop != "" {
				hops = append(hops, hop)
			}
		}
	}

	client = peer
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			break
		}
		client = ip.String()
		proxies = hops[i+1:]
		if !isTrustedProxyIP(ip) {
			break
		}
	}
	if len(proxies) == 0 {
		proxies = nil
	}
	return client, proxies
}

func EnrichContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := GetSessionIdentity(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if id == nil {
			id = identity.NewUser()
			if err := SaveSessionIdentity(r, w, id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Identity SessionId: %s, UserName: %s: Authenticated: %t",
			id.SessionId(), id.UserName(), id.Authenticated())

		id.SetAttribute(identity.AttrRemoteAddr, r.RemoteAddr)

		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}

		clientIp := remoteHost
		var proxies []string
		if remoteIsTrustedProxy(r.RemoteAddr) {
			clientIp, proxies = forwardedClient(r.Header.Values("X-Forwarded-For"), remoteHost)
		}
		id.SetAttribute(identity.AttrClientIp, clientIp)
		id.SetAttribute(identity.AttrProxies, proxies)

		next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
	})
}

func TransposeSPNEGOContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gid := goidentity.FromHTTPRequestContext(r)
		if gid != nil {
			id := identity.FromRequestCtx(r)
			id.SetUserName(gid.UserName())
			id.SetAuthenticated(gid.Authenticated())
			id.SetDomain(gid.Domain())
			id.SetAuthTime(gid.AuthTime())
			r = identity.AddToRequestCtx(id, r)
		}
		next.ServeHTTP(w, r)
	})
}
