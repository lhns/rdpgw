package config

import (
	"reflect"
	"testing"
)

func TestHeaderEnabled(t *testing.T) {
	cases := []struct {
		name           string
		authentication []string
		expected       bool
	}{
		{
			name:           "header_enabled",
			authentication: []string{"header"},
			expected:       true,
		},
		{
			name:           "header_with_others",
			authentication: []string{"openid", "header", "local"},
			expected:       true,
		},
		{
			name:           "header_not_enabled",
			authentication: []string{"openid", "local"},
			expected:       false,
		},
		{
			name:           "empty_authentication",
			authentication: []string{},
			expected:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ServerConfig{
				Authentication: tc.authentication,
			}

			result := config.HeaderEnabled()
			if result != tc.expected {
				t.Errorf("expected HeaderEnabled(): %v, got: %v", tc.expected, result)
			}
		})
	}
}

func TestAuthenticationConstants(t *testing.T) {
	// Test that the header authentication constant is correct
	if AuthenticationHeader != "header" {
		t.Errorf("incorrect authentication header constant: %v", AuthenticationHeader)
	}
}

func TestCheckDefaultSecrets(t *testing.T) {
	const placeholder = "thisisasessionkeyreplacethisjetzt"

	cases := []struct {
		name      string
		mutate    func(*Configuration)
		wantField string
	}{
		{
			name:      "session key",
			mutate:    func(c *Configuration) { c.Server.SessionKey = placeholder },
			wantField: "server.sessionkey",
		},
		{
			name:      "session encryption key",
			mutate:    func(c *Configuration) { c.Server.SessionEncryptionKey = placeholder },
			wantField: "server.sessionencryptionkey",
		},
		{
			name:      "paa signing key",
			mutate:    func(c *Configuration) { c.Security.PAATokenSigningKey = placeholder },
			wantField: "security.paatokensigningkey",
		},
		{
			name:      "paa encryption key",
			mutate:    func(c *Configuration) { c.Security.PAATokenEncryptionKey = placeholder },
			wantField: "security.paatokenencryptionkey",
		},
		{
			name:      "user signing key",
			mutate:    func(c *Configuration) { c.Security.UserTokenSigningKey = placeholder },
			wantField: "security.usertokensigningkey",
		},
		{
			name:      "user encryption key",
			mutate:    func(c *Configuration) { c.Security.UserTokenEncryptionKey = placeholder },
			wantField: "security.usertokenencryptionkey",
		},
		{
			name:      "query signing key",
			mutate:    func(c *Configuration) { c.Security.QueryTokenSigningKey = placeholder },
			wantField: "security.querytokensigningkey",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Configuration{}
			tc.mutate(c)
			err := checkDefaultSecrets(c)
			if err == nil {
				t.Fatalf("checkDefaultSecrets accepted a placeholder value in %s", tc.wantField)
			}
			if got := err.Error(); !contains(got, tc.wantField) {
				t.Errorf("error message %q should mention the field %q", got, tc.wantField)
			}
		})
	}
}

func TestCheckDefaultSecretsAllowsRandomValues(t *testing.T) {
	c := &Configuration{}
	c.Server.SessionKey = "5aa3a1568fe8421cd7e127d5ace28d2d"
	c.Server.SessionEncryptionKey = "d3ecd7e565e56e37e2f2e95b584d8c0c"
	c.Security.PAATokenSigningKey = "0123456789abcdef0123456789abcdef"
	if err := checkDefaultSecrets(c); err != nil {
		t.Errorf("checkDefaultSecrets rejected non-placeholder values: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestHeaderConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		headerConf  HeaderConfig
		shouldError bool
	}{
		{
			name: "valid_config",
			headerConf: HeaderConfig{
				UserHeader: "X-Forwarded-User",
			},
			shouldError: false,
		},
		{
			name: "missing_user_header",
			headerConf: HeaderConfig{
				EmailHeader: "X-Forwarded-Email",
			},
			shouldError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the configuration struct
			if tc.headerConf.UserHeader == "" && !tc.shouldError {
				t.Error("expected user header to be set")
			}
			if tc.headerConf.UserHeader != "" && tc.shouldError {
				t.Error("expected configuration to be invalid")
			}
		})
	}
}

func TestBasicAuthBackends(t *testing.T) {
	cases := []struct {
		authentication []string
		basic, ldap    bool
	}{
		{[]string{"local"}, true, false},
		{[]string{"basic"}, true, false},
		{[]string{"ldap"}, true, true},
		{[]string{"openid", "ntlm"}, false, false},
	}
	for _, tc := range cases {
		s := &ServerConfig{Authentication: tc.authentication}
		if got := s.BasicAuthEnabled(); got != tc.basic {
			t.Errorf("%v: BasicAuthEnabled() = %t, want %t", tc.authentication, got, tc.basic)
		}
		if got := s.LdapEnabled(); got != tc.ldap {
			t.Errorf("%v: LdapEnabled() = %t, want %t", tc.authentication, got, tc.ldap)
		}
	}
}

func TestLoadLdapFromEnv(t *testing.T) {
	cases := []struct {
		name   string
		groups string
		want   []string
	}{
		{"one group", "cn=rdp,ou=groups,dc=example,dc=com", []string{"cn=rdp,ou=groups,dc=example,dc=com"}},
		{"space separated groups", "cn=rdp,ou=groups,dc=example,dc=com cn=admin,ou=groups,dc=example,dc=com",
			[]string{"cn=rdp,ou=groups,dc=example,dc=com", "cn=admin,ou=groups,dc=example,dc=com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RDPGW_SERVER__AUTHENTICATION", "ldap")
			t.Setenv("RDPGW_CAPS__TOKEN_AUTH", "false")
			t.Setenv("RDPGW_LDAP__URL", "ldap://lldap.example.svc:3890")
			t.Setenv("RDPGW_LDAP__START_TLS", "true")
			t.Setenv("RDPGW_LDAP__USER_DN_TEMPLATE", "uid={username},ou=people,dc=example,dc=com")
			t.Setenv("RDPGW_LDAP__REQUIRED_GROUPS", tc.groups)
			Conf = Configuration{}

			c := Load("does-not-exist.yaml")
			if !c.Server.LdapEnabled() {
				t.Fatalf("ldap not enabled, authentication = %v", c.Server.Authentication)
			}
			if c.Ldap.Url != "ldap://lldap.example.svc:3890" || !c.Ldap.StartTls ||
				c.Ldap.UserDnTemplate != "uid={username},ou=people,dc=example,dc=com" {
				t.Errorf("unexpected ldap config %+v", c.Ldap)
			}
			if !reflect.DeepEqual(c.Ldap.RequiredGroups, tc.want) {
				t.Errorf("RequiredGroups = %q, want %q", c.Ldap.RequiredGroups, tc.want)
			}
		})
	}
}

func TestCheckBasicAuthTransport(t *testing.T) {
	proxies := []string{"10.0.0.0/8"}
	cases := []struct {
		name    string
		s       ServerConfig
		wantErr bool
	}{
		{"basic over tls", ServerConfig{Authentication: []string{"ldap"}, Tls: TlsAuto}, false},
		{"basic on plain http", ServerConfig{Authentication: []string{"ldap"}, Tls: TlsDisable}, true},
		{"local on plain http", ServerConfig{Authentication: []string{"local"}, Tls: TlsDisable}, true},
		{"basic behind a terminating proxy", ServerConfig{Authentication: []string{"ldap"}, Tls: TlsDisable, TlsTerminatedByProxy: true, TrustedProxies: proxies}, false},
		{"opt-in without trusted proxies", ServerConfig{Authentication: []string{"ldap"}, Tls: TlsDisable, TlsTerminatedByProxy: true}, true},
		{"openid on plain http", ServerConfig{Authentication: []string{"openid"}, Tls: TlsDisable}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkBasicAuthTransport(&tc.s); (err != nil) != tc.wantErr {
				t.Errorf("checkBasicAuthTransport() = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestLoadLockoutDefaultsAndEnv(t *testing.T) {
	t.Setenv("RDPGW_SERVER__AUTHENTICATION", "ldap")
	t.Setenv("RDPGW_CAPS__TOKEN_AUTH", "false")
	t.Setenv("RDPGW_LOCKOUT__USER_MAX_FAILURES", "3")
	Conf = Configuration{}

	c := Load("does-not-exist.yaml")
	want := LockoutConfig{IpMaxFailures: 10, IpDuration: 3600, UserMaxFailures: 3, UserDuration: 300, Window: 900}
	if c.Lockout != want {
		t.Errorf("Lockout = %+v, want %+v", c.Lockout, want)
	}
}

func TestCheckLdap(t *testing.T) {
	cases := []struct {
		name    string
		c       Configuration
		wantErr bool
	}{
		{"unsigned without token auth", Configuration{Server: ServerConfig{Authentication: []string{"ldap"}, HostSelection: "unsigned"}}, false},
		{"token auth on", Configuration{Server: ServerConfig{Authentication: []string{"ldap"}}, Caps: RDGCapsConfig{TokenAuth: true}}, true},
		{"signed hosts", Configuration{Server: ServerConfig{Authentication: []string{"ldap"}, HostSelection: HostSelectionSigned}}, true},
		{"stacked with openid keeps token auth", Configuration{Server: ServerConfig{Authentication: []string{"openid", "ldap"}, HostSelection: "unsigned"}, Caps: RDGCapsConfig{TokenAuth: true}}, false},
		{"stacked still refuses signed", Configuration{Server: ServerConfig{Authentication: []string{"openid", "ldap"}, HostSelection: HostSelectionSigned}, Caps: RDGCapsConfig{TokenAuth: true}}, true},
		{"stacked with local", Configuration{Server: ServerConfig{Authentication: []string{"ldap", "local"}, HostSelection: "unsigned"}}, true},
		{"other modes untouched", Configuration{Server: ServerConfig{Authentication: []string{"openid"}}, Caps: RDGCapsConfig{TokenAuth: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkLdap(&tc.c); (err != nil) != tc.wantErr {
				t.Errorf("checkLdap() = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestCheckLockout(t *testing.T) {
	valid := LockoutConfig{IpMaxFailures: 10, IpDuration: 3600, UserMaxFailures: 5, UserDuration: 300, Window: 900}
	cases := []struct {
		name    string
		modify  func(*LockoutConfig)
		wantErr bool
	}{
		{"defaults", func(*LockoutConfig) {}, false},
		{"zero window", func(l *LockoutConfig) { l.Window = 0 }, true},
		{"zero ip duration", func(l *LockoutConfig) { l.IpDuration = 0 }, true},
		{"negative user duration", func(l *LockoutConfig) { l.UserDuration = -1 }, true},
		{"disabled limiters need no durations", func(l *LockoutConfig) { *l = LockoutConfig{} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := valid
			tc.modify(&l)
			if err := checkLockout(&l); (err != nil) != tc.wantErr {
				t.Errorf("checkLockout(%+v) = %v, wantErr %t", l, err, tc.wantErr)
			}
		})
	}
}

func TestCheckStacking(t *testing.T) {
	stacked := func(mode, hosts string, auth ...string) Configuration {
		return Configuration{Server: ServerConfig{Authentication: auth, HostSelection: hosts, UnauthenticatedRequests: mode}}
	}
	cases := []struct {
		name    string
		c       Configuration
		wantErr bool
	}{
		{"openid+local default", stacked("", "roundrobin", "openid", "local"), false},
		{"openid+ldap paa", stacked("paa", "unsigned", "openid", "ldap"), false},
		{"openid+ldap challenge", stacked("challenge", "unsigned", "openid", "ldap"), false},
		{"normalized", stacked("  Challenge ", "unsigned", "openid", "local"), false},
		{"invalid value", stacked("both", "unsigned", "openid", "local"), true},
		{"set without stacking, openid only", stacked("paa", "roundrobin", "openid"), true},
		{"set without stacking, ldap only", stacked("challenge", "unsigned", "ldap"), true},
		{"blank is unset", stacked("  ", "roundrobin", "openid"), false},
		{"with kerberos", stacked("", "unsigned", "openid", "local", "kerberos"), true},
		{"with ntlm", stacked("", "unsigned", "openid", "local", "ntlm"), true},
		{"with header", stacked("", "unsigned", "openid", "local", "header"), true},
		{"signed", stacked("", "signed", "openid", "local"), true},
		{"any", stacked("", "any", "openid", "ldap"), true},
		{"kerberos+local without openid is not stacked", stacked("", "any", "local", "kerberos"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkStacking(&tc.c); (err != nil) != tc.wantErr {
				t.Errorf("checkStacking() = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestUnauthenticatedMode(t *testing.T) {
	if got := (&ServerConfig{Authentication: []string{"openid", "ldap"}}).UnauthenticatedMode(); got != UnauthenticatedPAA {
		t.Errorf("stacked default = %q, want paa", got)
	}
	if got := (&ServerConfig{Authentication: []string{"openid"}}).UnauthenticatedMode(); got != "" {
		t.Errorf("not stacked = %q, want empty", got)
	}
}

func TestLoadUnauthenticatedRequestsFromEnv(t *testing.T) {
	t.Setenv("RDPGW_SERVER__AUTHENTICATION", "openid ldap")
	t.Setenv("RDPGW_SERVER__HOST_SELECTION", "unsigned")
	t.Setenv("RDPGW_SERVER__UNAUTHENTICATED_REQUESTS", " Challenge ")
	Conf = Configuration{}

	c := Load("does-not-exist.yaml")
	if !c.Server.Stacked() {
		t.Fatalf("not stacked, authentication = %v", c.Server.Authentication)
	}
	if got := c.Server.UnauthenticatedMode(); got != UnauthenticatedChallenge {
		t.Errorf("UnauthenticatedMode() = %q, want challenge", got)
	}
}
