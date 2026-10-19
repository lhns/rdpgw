package main

import (
	"log"
	"net/http"
	"time"

	"github.com/bolkedebruin/gokrb5/v8/keytab"
	"github.com/bolkedebruin/gokrb5/v8/service"
	"github.com/bolkedebruin/gokrb5/v8/spnego"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/web"
	"github.com/gorilla/mux"
)

const basicScheme = "(?i)^basic "

// newBasicAuthHandler builds the Basic handler for the configured backend
// (ldap or the local PAM socket).
func newBasicAuthHandler(conf *config.Configuration) *web.BasicAuthHandler {
	var backend web.PasswordAuthenticator = &web.SocketAuthenticator{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
	if conf.Server.LdapEnabled() {
		log.Printf("enabling basic authentication against %s", conf.Ldap.Url)
		l, err := web.NewLDAPAuthenticator(web.LDAPConfig{
			URL:            conf.Ldap.Url,
			StartTLS:       conf.Ldap.StartTls,
			CAFile:         conf.Ldap.CaFile,
			UserDNTemplate: conf.Ldap.UserDnTemplate,
			RequiredGroups: conf.Ldap.RequiredGroups,
			Timeout:        time.Second * time.Duration(conf.Server.BasicAuthTimeout),
		})
		if err != nil {
			log.Fatalf("Cannot configure ldap authentication: %s", err)
		}
		if !l.Encrypted() {
			log.Printf("ldap: passwords are sent to %s unencrypted; use ldaps:// or starttls unless the path is trusted", conf.Ldap.Url)
		}
		if len(conf.Ldap.RequiredGroups) == 0 {
			log.Printf("ldap: no required groups configured, every user that can bind may use the gateway")
		}
		backend = l
	} else {
		log.Printf("enabling basic authentication")
	}
	lo := conf.Lockout
	window := time.Second * time.Duration(lo.Window)
	q := &web.BasicAuthHandler{
		Authenticator:   backend,
		RequireProxyTLS: conf.Server.Tls == config.TlsDisable,
		IPLimiter:       web.NewFailureLimiter(lo.IpMaxFailures, window, time.Second*time.Duration(lo.IpDuration)),
		UserLimiter:     web.NewFailureLimiter(lo.UserMaxFailures, window, time.Second*time.Duration(lo.UserDuration)),
	}
	if q.RequireProxyTLS {
		log.Printf("TLS disabled: basic auth is accepted only from trusted proxies that terminated TLS")
	}
	return q
}

// newGateways builds the protocol gateways from the configuration. gwBasic is
// nil unless openid is stacked with basic auth; then gw is the PAA gateway and
// gwBasic serves Basic clients. They are separate because a PAA gateway
// demands the token and rewrites the user from it, and the decision between
// them must not depend on identity state: a browser session cookie would
// otherwise count as basic auth.
func newGateways(conf *config.Configuration) (gw, gwBasic *protocol.Gateway) {
	gw = &protocol.Gateway{
		RedirectFlags: protocol.RedirectFlags{
			Clipboard:  conf.Caps.EnableClipboard,
			Drive:      conf.Caps.EnableDrive,
			Printer:    conf.Caps.EnablePrinter,
			Port:       conf.Caps.EnablePort,
			Pnp:        conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll:  conf.Caps.RedirectAll,
		},
		IdleTimeout:   conf.Caps.IdleTimeout,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		TokenAuth:     conf.Caps.TokenAuth,
		ReceiveBuf:    conf.Server.ReceiveBuf,
		SendBuf:       conf.Server.SendBuf,
	}
	if conf.Server.Stacked() {
		basicGw := *gw
		gwBasic = &basicGw
		// Basic clients send no extended auth capabilities.
		gwBasic.TokenAuth = false
		gwBasic.SmartCardAuth = false
		gwBasic.CheckHost = security.CheckHost

		// Load already requires caps.tokenauth with openid; the PAA side of
		// the boundary must not depend on that.
		gw.TokenAuth = true
	}
	if gw.TokenAuth {
		gw.CheckPAACookie = security.CheckPAACookie
		gw.CheckHost = security.CheckSession(security.CheckHost)
	} else {
		gw.CheckHost = security.CheckHost
	}
	return gw, gwBasic
}

// registerStacked routes openid (PAA token in the tunnel) and basic auth on
// one endpoint. Routing on the Authorization scheme is the security boundary:
// Basic is always verified and served by gwBasic, everything else by gwPAA,
// which needs a valid token.
func registerStacked(rdp *mux.Router, conf *config.Configuration, gwPAA, gwBasic *protocol.Gateway, basic *web.BasicAuthHandler) {
	if conf.Server.UnauthenticatedMode() == config.UnauthenticatedChallenge {
		auth := web.NewAuthMux()
		auth.Register([]string{web.BasicChallenge}, nil)
		rdp.MatcherFunc(web.NoAuthz).HandlerFunc(auth.SetAuthenticate)
	}
	rdp.NewRoute().HeadersRegexp("Authorization", basicScheme).HandlerFunc(basic.BasicAuth(gwBasic.HandleGatewayProtocol))
	rdp.NewRoute().HandlerFunc(gwPAA.HandleGatewayProtocol)
}

// registerGateway wires the authentication schemes onto the gateway endpoint.
// Routes match in registration order. basic is nil unless basic auth is
// enabled; gwBasic is nil unless openid is stacked with it (see newGateways).
func registerGateway(rdp *mux.Router, conf *config.Configuration, gw, gwBasic *protocol.Gateway, basic *web.BasicAuthHandler) {
	if conf.Server.Stacked() {
		log.Printf("enabling openid stacked with basic authentication, unauthenticated requests: %s", conf.Server.UnauthenticatedMode())
		registerStacked(rdp, conf, gw, gwBasic, basic)
		return
	}

	// only enable un-auth endpoint for openid only config
	if conf.Server.OpenIDEnabled() && !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() && !conf.Server.HeaderEnabled() {
		rdp.Name("gw").HandlerFunc(gw.HandleGatewayProtocol)
	}

	// only enable un-auth endpoint for header only config
	if conf.Server.HeaderEnabled() && !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() && !conf.Server.OpenIDEnabled() {
		rdp.Name("gw").HandlerFunc(gw.HandleGatewayProtocol)
	}

	// for stacking of authentication
	auth := web.NewAuthMux()
	rdp.MatcherFunc(web.NoAuthz).HandlerFunc(auth.SetAuthenticate)

	// ntlm
	if conf.Server.NtlmEnabled() {
		log.Printf("enabling NTLM authentication")
		ntlm := web.NTLMAuthHandler{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
		rdp.NewRoute().HeadersRegexp("Authorization", "NTLM").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		auth.Register([]string{`NTLM`, `Negotiate`}, func(r *http.Request) bool {
			return r.Header.Get("Sec-WebSocket-Protocol") != "binary" // rdp client for ios is incompatible with this NTLM method.
		})
	}

	// basic auth
	if conf.Server.BasicAuthEnabled() {
		rdp.NewRoute().HeadersRegexp("Authorization", basicScheme).HandlerFunc(basic.BasicAuth(gw.HandleGatewayProtocol))
		auth.Register([]string{web.BasicChallenge}, nil)
	}

	// spnego / kerberos
	if conf.Server.KerberosEnabled() {
		log.Printf("enabling kerberos authentication")
		keytab, err := keytab.Load(conf.Kerberos.Keytab)
		if err != nil {
			log.Fatalf("Cannot load keytab: %s", err)
		}
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").Handler(
			spnego.SPNEGOKRB5Authenticate(web.TransposeSPNEGOContext(http.HandlerFunc(gw.HandleGatewayProtocol)),
				keytab,
				service.Logger(log.Default())))
		auth.Register([]string{"Negotiate"}, nil)
	}
}
