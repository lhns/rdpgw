package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPUsernamePlaceholder is replaced by the (DN-escaped) username in
// LDAPConfig.UserDNTemplate.
const LDAPUsernamePlaceholder = "{username}"

// ldapUsername bounds what a client may send as a username before it is
// spliced into a DN. Escaping alone would be enough for safety; the
// allow-list also keeps the DN predictable and the logs readable.
var ldapUsername = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

type LDAPConfig struct {
	// URL is ldap://host[:port] or ldaps://host[:port].
	URL string
	// StartTLS upgrades an ldap:// connection before binding.
	StartTLS bool
	// CAFile is a PEM bundle used instead of the system roots to verify the
	// LDAP server certificate.
	CAFile string
	// UserDNTemplate is the DN to bind as, e.g.
	// uid={username},ou=people,dc=example,dc=com.
	UserDNTemplate string
	// RequiredGroups are group DNs; the user's memberOf must contain one of
	// them. Empty admits every user that can bind.
	RequiredGroups []string
	Timeout        time.Duration
}

// LDAPAuthenticator verifies a password by binding as the user, then checks
// group membership on the user's own entry with that same bind. It needs no
// service account.
type LDAPAuthenticator struct {
	url            string
	ldaps          bool
	startTLS       bool
	tlsConfig      *tls.Config
	userDNTemplate string
	requiredGroups []*ldap.DN
	timeout        time.Duration
}

func NewLDAPAuthenticator(c LDAPConfig) (*LDAPAuthenticator, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid ldap url %q: %w", c.URL, err)
	}
	switch u.Scheme {
	case "ldap":
	case "ldaps":
		if c.StartTLS {
			return nil, errors.New("starttls cannot be used with an ldaps:// url")
		}
	default:
		return nil, fmt.Errorf("ldap url %q must start with ldap:// or ldaps://", c.URL)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("ldap url %q has no host", c.URL)
	}

	if strings.Count(c.UserDNTemplate, LDAPUsernamePlaceholder) != 1 {
		return nil, fmt.Errorf("ldap user dn template must contain %s exactly once", LDAPUsernamePlaceholder)
	}
	if _, err := ldap.ParseDN(strings.Replace(c.UserDNTemplate, LDAPUsernamePlaceholder, "user", 1)); err != nil {
		return nil, fmt.Errorf("invalid ldap user dn template %q: %w", c.UserDNTemplate, err)
	}

	groups := make([]*ldap.DN, 0, len(c.RequiredGroups))
	for _, g := range c.RequiredGroups {
		dn, err := ldap.ParseDN(g)
		if err != nil {
			return nil, fmt.Errorf("invalid ldap group dn %q: %w", g, err)
		}
		groups = append(groups, dn)
	}

	tlsConfig := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read ldap ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in ldap ca file %s", c.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	if c.Timeout <= 0 {
		return nil, errors.New("ldap timeout must be positive")
	}

	return &LDAPAuthenticator{
		url:            c.URL,
		ldaps:          u.Scheme == "ldaps",
		startTLS:       c.StartTLS,
		tlsConfig:      tlsConfig,
		userDNTemplate: c.UserDNTemplate,
		requiredGroups: groups,
		timeout:        c.Timeout,
	}, nil
}

// Encrypted reports whether credentials are protected on the way to the
// LDAP server.
func (a *LDAPAuthenticator) Encrypted() bool {
	return a.startTLS || a.ldaps
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	// An empty password would be an unauthenticated bind (RFC 4513 5.1.2),
	// which many servers answer with success.
	if password == "" || !ldapUsername.MatchString(username) {
		return false, nil
	}
	userDN := strings.Replace(a.userDNTemplate, LDAPUsernamePlaceholder, ldap.EscapeDN(username), 1)

	conn, err := a.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if err := conn.Bind(userDN, password); err != nil {
		if bindRefused(err) {
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				log.Printf("auth: method=ldap bind_refused user=%q error=%q", username, err)
			}
			return false, nil
		}
		return false, fmt.Errorf("ldap bind: %w", err)
	}

	if len(a.requiredGroups) == 0 {
		return true, nil
	}

	res, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(a.timeout.Seconds()), false, "(objectClass=*)", []string{"memberOf"}, nil))
	if err != nil {
		return false, fmt.Errorf("ldap search for %s: %w", userDN, err)
	}
	if len(res.Entries) != 1 {
		return false, fmt.Errorf("ldap search for %s returned %d entries", userDN, len(res.Entries))
	}
	for _, v := range res.Entries[0].GetEqualFoldAttributeValues("memberOf") {
		member, err := ldap.ParseDN(v)
		if err != nil {
			continue
		}
		for _, g := range a.requiredGroups {
			if g.EqualFold(member) {
				return true, nil
			}
		}
	}
	return false, ErrAccessDenied
}

// bindRefused tells a refused bind, which counts against the lockout, from
// a server that could not answer. Servers report wrong or locked passwords
// with codes other than invalidCredentials too (e.g. 19, 53), so every
// server result code except busy and unavailable is a refusal. Client-side
// errors (network, TLS, timeout) use codes from 200 up.
func bindRefused(err error) bool {
	var e *ldap.Error
	if !errors.As(err, &e) || e.ResultCode >= 200 {
		return false
	}
	return e.ResultCode != ldap.LDAPResultBusy && e.ResultCode != ldap.LDAPResultUnavailable
}

func (a *LDAPAuthenticator) dial(ctx context.Context) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: a.timeout}
	if d, ok := ctx.Deadline(); ok {
		dialer.Deadline = d
	}
	conn, err := ldap.DialURL(a.url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(a.tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	conn.SetTimeout(a.timeout)
	if a.startTLS {
		if err := conn.StartTLS(a.tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}
	return conn, nil
}
