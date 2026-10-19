package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// knownDefaultSecrets is the list of placeholder session/token-key values
// that appear in README.md and the dev compose files. Operators that
// copy-paste the examples into a real deployment would be running with
// widely-published keys, so the gateway refuses to start when one of these
// is set for any of the session-/token-binding fields.
var knownDefaultSecrets = []string{
	"thisisasessionkeyreplacethisjetzt",
	"thisisasessionkeyreplacethisjetz",
	"thisisasessionkeyreplacethisnunu!",
	"thisisasessionkeyreplacethisnunu",
	"thisisasessionencryptionkey12345",
}

func checkDefaultSecrets(c *Configuration) error {
	fields := []struct {
		name  string
		value string
	}{
		{"server.sessionkey", c.Server.SessionKey},
		{"server.sessionencryptionkey", c.Server.SessionEncryptionKey},
		{"security.paatokensigningkey", c.Security.PAATokenSigningKey},
		{"security.paatokenencryptionkey", c.Security.PAATokenEncryptionKey},
		{"security.usertokensigningkey", c.Security.UserTokenSigningKey},
		{"security.usertokenencryptionkey", c.Security.UserTokenEncryptionKey},
		{"security.querytokensigningkey", c.Security.QueryTokenSigningKey},
	}
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		for _, def := range knownDefaultSecrets {
			if f.value == def {
				return fmt.Errorf("%s is set to a known placeholder value (%q); replace it with a unique secret before starting", f.name, def)
			}
		}
	}
	return nil
}

const (
	TlsDisable = "disable"
	TlsAuto    = "auto"

	HostSelectionSigned     = "signed"
	HostSelectionRoundRobin = "roundrobin"

	SessionStoreCookie = "cookie"
	SessionStoreFile   = "file"

	AuthenticationOpenId   = "openid"
	AuthenticationBasic    = "local"
	AuthenticationKerberos = "kerberos"
	AuthenticationHeader   = "header"
	AuthenticationLdap     = "ldap"
)

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
	Kerberos KerberosConfig `koanf:"kerberos"`
	Header   HeaderConfig   `koanf:"header"`
	Ldap     LdapConfig     `koanf:"ldap"`
	Lockout  LockoutConfig  `koanf:"lockout"`
	Caps     RDGCapsConfig  `koanf:"caps"`
	Security SecurityConfig `koanf:"security"`
	Client   ClientConfig   `koanf:"client"`
}

type ServerConfig struct {
	GatewayAddress       string   `koanf:"gatewayaddress"`
	Port                 int      `koanf:"port"`
	BindAddress          string   `koanf:"bindaddress"`
	CertFile             string   `koanf:"certfile"`
	KeyFile              string   `koanf:"keyfile"`
	Hosts                []string `koanf:"hosts"`
	HostSelection        string   `koanf:"hostselection"`
	SessionKey           string   `koanf:"sessionkey"`
	SessionEncryptionKey string   `koanf:"sessionencryptionkey"`
	SessionStore         string   `koanf:"sessionstore"`
	MaxSessionLength     int      `koanf:"maxsessionlength"`
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"receivebuf"`
	Tls                  string   `koanf:"tls"`
	Authentication       []string `koanf:"authentication"`
	AuthSocket           string   `koanf:"authsocket"`
	BasicAuthTimeout     int      `koanf:"basicauthtimeout"`
	// AllowedDestinationPorts gates the TCP ports `hostselection: any` may
	// forward to. Empty defaults to {3389}. Ignored for the curated host
	// modes (roundrobin, signed, unsigned).
	AllowedDestinationPorts []int `koanf:"alloweddestinationports"`
	// AllowPrivateDestinations, when true, lets `hostselection: any`
	// forward to loopback, RFC1918, link-local, and IPv6 ULA targets.
	// Default false.
	AllowPrivateDestinations bool `koanf:"allowprivatedestinations"`
	// TrustedProxies is the CIDR allow-list of upstream proxies whose
	// X-Forwarded-For header is honored when deriving the client IP.
	// Empty (the default) makes the gateway ignore X-Forwarded-For
	// entirely and use r.RemoteAddr. The client is the rightmost
	// X-Forwarded-For address not in this list, so list every proxy hop.
	TrustedProxies []string `koanf:"trustedproxies"`
	// TlsTerminatedByProxy allows basic authentication with tls=disable.
	// Credentials are then accepted only from a TrustedProxies peer that
	// reports X-Forwarded-Proto: https.
	TlsTerminatedByProxy bool `koanf:"tlsterminatedbyproxy"`
}

type KerberosConfig struct {
	Keytab   string `koanf:"keytab"`
	Krb5Conf string `koanf:"krb5conf"`
}

type OpenIDConfig struct {
	ProviderUrl  string `koanf:"providerurl"`
	ClientId     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
}

type HeaderConfig struct {
	UserHeader      string `koanf:"userheader"`
	UserIdHeader    string `koanf:"useridheader"`
	EmailHeader     string `koanf:"emailheader"`
	DisplayNameHeader string `koanf:"displaynameheader"`
	// TrustedProxies is the CIDR allow-list of upstream proxies allowed to
	// stamp UserHeader (and friends). Empty disables header auth at runtime.
	TrustedProxies  []string `koanf:"trustedproxies"`
}

// LdapConfig configures `authentication: ldap`: HTTP Basic credentials
// verified by binding to an LDAP server as the user.
type LdapConfig struct {
	// Url is ldap://host:port or ldaps://host:port.
	Url string `koanf:"url"`
	// StartTls upgrades an ldap:// connection before binding.
	StartTls bool `koanf:"starttls"`
	// CaFile is a PEM bundle that replaces the system roots for the LDAP
	// server certificate.
	CaFile string `koanf:"cafile"`
	// UserDnTemplate is the bind DN, with {username} replaced by the
	// escaped username, e.g. uid={username},ou=people,dc=example,dc=com.
	UserDnTemplate string `koanf:"userdntemplate"`
	// RequiredGroups lists group DNs; the user's memberOf must contain one.
	// Empty admits every user that can bind.
	RequiredGroups []string `koanf:"requiredgroups"`
}

// LockoutConfig throttles basic authentication (local, ldap). Attempts
// beyond MaxFailures within Window lock the client IP or the username out
// for the given duration. Durations are in seconds; a zero max disables.
type LockoutConfig struct {
	IpMaxFailures   int `koanf:"ipmaxfailures"`
	IpDuration      int `koanf:"ipduration"`
	UserMaxFailures int `koanf:"usermaxfailures"`
	UserDuration    int `koanf:"userduration"`
	Window          int `koanf:"window"`
}

type RDGCapsConfig struct {
	SmartCardAuth   bool `koanf:"smartcardauth"`
	TokenAuth       bool `koanf:"tokenauth"`
	IdleTimeout     int  `koanf:"idletimeout"`
	RedirectAll     bool `koanf:"redirectall"`
	DisableRedirect bool `koanf:"disableredirect"`
	EnableClipboard bool `koanf:"enableclipboard"`
	EnablePrinter   bool `koanf:"enableprinter"`
	EnablePort      bool `koanf:"enableport"`
	EnablePnp       bool `koanf:"enablepnp"`
	EnableDrive     bool `koanf:"enabledrive"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey  string `koanf:"paatokenencryptionkey"`
	PAATokenSigningKey     string `koanf:"paatokensigningkey"`
	UserTokenEncryptionKey string `koanf:"usertokenencryptionkey"`
	UserTokenSigningKey    string `koanf:"usertokensigningkey"`
	QueryTokenSigningKey   string `koanf:"querytokensigningkey"`
	QueryTokenIssuer       string `koanf:"querytokenissuer"`
	VerifyClientIp         bool   `koanf:"verifyclientip"`
	EnableUserToken        bool   `koanf:"enableusertoken"`
}

type ClientConfig struct {
	Defaults string `koanf:"defaults"`
	// kept for backwards compatibility
	UsernameTemplate string `koanf:"usernametemplate"`
	SplitUserDomain  bool   `koanf:"splituserdomain"`
	NoUsername       bool   `koanf:"nousername"`
	SigningCert      string `koanf:"signingcert"`
	SigningKey       string `koanf:"signingkey"`
	// RdpOverridableKeys is the operator allow-list of RDP setting keys that
	// the /connect endpoint may override from URL query parameters. Empty
	// disables URL-based overrides. Entries are normalized (lowercase, no
	// whitespace), so "use multimon" and "usemultimon" are equivalent.
	RdpOverridableKeys []string `koanf:"rdpoverridablekeys"`
}

func ToCamel(s string) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s))
	var capNext bool = true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
			if v == '.' {
				n.WriteByte(v)
			}
		}
	}
	return n.String()
}

var Conf Configuration

func Load(configFile string) Configuration {

	var k = koanf.New(".")

	k.Load(confmap.Provider(map[string]interface{}{
		"Server.Tls":                 "auto",
		"Server.Port":                443,
		"Server.BindAddress":         "",
		"Server.SessionStore":        "cookie",
		"Server.HostSelection":       "roundrobin",
		"Server.Authentication":      "openid",
		"Server.AuthSocket":          "/tmp/rdpgw-auth.sock",
		"Server.BasicAuthTimeout":    5,
		"Lockout.IpMaxFailures":      10,
		"Lockout.IpDuration":         3600,
		"Lockout.UserMaxFailures":    5,
		"Lockout.UserDuration":       300,
		"Lockout.Window":             900,
		"Client.NetworkAutoDetect":   1,
		"Client.BandwidthAutoDetect": 1,
		"Security.VerifyClientIp":    true,
		"Caps.TokenAuth":             true,
	}, "."), nil)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file %s not found, using defaults and environment", configFile)
	} else {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			log.Fatalf("Error loading config from file: %v", err)
		}
	}

	if err := k.Load(env.ProviderWithValue("RDPGW_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "RDPGW_")), "__", ".", -1)
		key = ToCamel(key)

		v = strings.Trim(v, " ")

		// handle lists
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}
		return key, v

	}), nil); err != nil {
		log.Fatalf("Error loading config from environment: %v", err)
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Server", &Conf.Server, koanfTag)
	k.UnmarshalWithConf("OpenId", &Conf.OpenId, koanfTag)
	k.UnmarshalWithConf("Header", &Conf.Header, koanfTag)
	k.UnmarshalWithConf("Caps", &Conf.Caps, koanfTag)
	k.UnmarshalWithConf("Security", &Conf.Security, koanfTag)
	k.UnmarshalWithConf("Client", &Conf.Client, koanfTag)
	k.UnmarshalWithConf("Kerberos", &Conf.Kerberos, koanfTag)
	k.UnmarshalWithConf("Ldap", &Conf.Ldap, koanfTag)
	k.UnmarshalWithConf("Lockout", &Conf.Lockout, koanfTag)

	if err := checkDefaultSecrets(&Conf); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if len(Conf.Security.PAATokenEncryptionKey) != 32 {
		Conf.Security.PAATokenEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokenencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Security.PAATokenSigningKey) != 32 {
		Conf.Security.PAATokenSigningKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokensigningkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Security.EnableUserToken {
		if len(Conf.Security.UserTokenEncryptionKey) != 32 {
			Conf.Security.UserTokenEncryptionKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokenencryptionkey` specified (empty or not 32 characters). Setting to random")
		}
	}

	if len(Conf.Server.SessionKey) != 32 {
		Conf.Server.SessionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Server.SessionEncryptionKey) != 32 {
		Conf.Server.SessionEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Server.HostSelection == "signed" && len(Conf.Security.QueryTokenSigningKey) == 0 {
		log.Fatalf("host selection is set to `signed` but `querytokensigningkey` is not set")
	}

	if err := checkBasicAuthTransport(&Conf.Server); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if err := checkLdap(&Conf); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if err := checkLockout(&Conf.Lockout); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if Conf.Server.LdapEnabled() && (Conf.Server.matchAuth("local") || Conf.Server.matchAuth("basic")) {
		log.Fatalf("local and ldap authentication both use basic auth and are not stackable")
	}

	if Conf.Server.NtlmEnabled() && Conf.Server.KerberosEnabled() {
		log.Fatalf("ntlm and kerberos authentication are not stackable")
	}

	if !Conf.Caps.TokenAuth && Conf.Server.OpenIDEnabled() {
		log.Fatalf("openid is configured but tokenauth disabled")
	}

	if Conf.Server.KerberosEnabled() && Conf.Kerberos.Keytab == "" {
		log.Fatalf("kerberos is configured but no keytab was specified")
	}

	if Conf.Server.HeaderEnabled() && Conf.Header.UserHeader == "" {
		log.Fatalf("header authentication is configured but no user header was specified")
	}

	// prepend '//' if required for URL parsing
	if !strings.Contains(Conf.Server.GatewayAddress, "//") {
		Conf.Server.GatewayAddress = "//" + Conf.Server.GatewayAddress
	}

	return Conf
}

// checkBasicAuthTransport keeps basic auth credentials off plain HTTP unless
// the operator vouches for a TLS-terminating proxy in front of rdpgw.
func checkBasicAuthTransport(s *ServerConfig) error {
	if s.TlsTerminatedByProxy && len(s.TrustedProxies) == 0 {
		return fmt.Errorf("server.tlsterminatedbyproxy needs server.trustedproxies to name the terminating proxy")
	}
	if s.BasicAuthEnabled() && s.Tls == TlsDisable && !s.TlsTerminatedByProxy {
		return fmt.Errorf("basic authentication (local, ldap) with tls=disable needs server.tlsterminatedbyproxy: true behind a TLS-terminating proxy")
	}
	return nil
}

// checkLdap rejects combinations in which no ldap client could connect.
func checkLdap(c *Configuration) error {
	if !c.Server.LdapEnabled() {
		return nil
	}
	if c.Caps.TokenAuth {
		return fmt.Errorf("ldap authentication needs caps.tokenauth: false; basic auth clients carry no PAA token")
	}
	if c.Server.HostSelection == HostSelectionSigned {
		return fmt.Errorf("ldap authentication cannot use hostselection: signed, which needs a PAA token")
	}
	return nil
}

func checkLockout(l *LockoutConfig) error {
	if l.IpMaxFailures > 0 && (l.IpDuration <= 0 || l.Window <= 0) {
		return fmt.Errorf("lockout.ipduration and lockout.window must be positive when lockout.ipmaxfailures is set")
	}
	if l.UserMaxFailures > 0 && (l.UserDuration <= 0 || l.Window <= 0) {
		return fmt.Errorf("lockout.userduration and lockout.window must be positive when lockout.usermaxfailures is set")
	}
	return nil
}

func (s *ServerConfig) OpenIDEnabled() bool {
	return s.matchAuth("openid")
}

func (s *ServerConfig) KerberosEnabled() bool {
	return s.matchAuth("kerberos")
}

// BasicAuthEnabled reports whether HTTP Basic is accepted on the gateway
// endpoint, whichever backend verifies it.
func (s *ServerConfig) BasicAuthEnabled() bool {
	return s.matchAuth("local") || s.matchAuth("basic") || s.LdapEnabled()
}

func (s *ServerConfig) LdapEnabled() bool {
	return s.matchAuth(AuthenticationLdap)
}

func (s *ServerConfig) NtlmEnabled() bool {
	return s.matchAuth("ntlm")
}

func (s *ServerConfig) HeaderEnabled() bool {
	return s.matchAuth("header")
}

func (s *ServerConfig) matchAuth(needle string) bool {
	for _, q := range s.Authentication {
		if q == needle {
			return true
		}
	}
	return false
}
