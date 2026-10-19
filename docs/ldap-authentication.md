# LDAP Authentication

With `ldap`, the RDP client sends gateway credentials with HTTP Basic and rdpgw
verifies them by binding to an LDAP server as that user. It runs inside rdpgw:
no `rdpgw-auth` helper, no PAM, no root.

## Clients

Only clients that answer a `Basic` challenge can use it. These are the
Microsoft Windows App / Remote Desktop clients for **iOS, Android and macOS**.
The Windows client `mstsc` (and everything built on `mstscax.dll`) does not
send Basic, even with `gatewaycredentialssource:i:3`; use OpenID Connect,
NTLM or Kerberos for it.

## How it works

1. The client's first request has no credentials; rdpgw answers
   `401` with `WWW-Authenticate: Basic`.
2. The client resends with `Authorization: Basic`.
3. rdpgw binds as `UserDnTemplate` with `{username}` replaced. A failed bind is
   a wrong password.
4. If `RequiredGroups` is set, rdpgw reads `memberOf` from the user's own entry,
   with the user's own bind, and requires one of the listed group DNs. No
   service account is needed; the directory must let users read their own
   `memberOf` (lldap, OpenLDAP with the memberof overlay and Active Directory do).

Usernames must match `[A-Za-z0-9._@-]{1,64}` and are DN-escaped; `DOMAIN\user`
is refused, so users enter the plain username. Empty passwords are refused
before any bind, because an empty-password simple bind is an unauthenticated
bind that many servers accept. Any LDAP result code other than busy or
unavailable counts as a wrong password, so password-policy refusals count
against the lockout too.

## Configuration

```yaml
Server:
  Authentication:
    - ldap
  # Seconds for each LDAP connect and operation.
  BasicAuthTimeout: 5
  HostSelection: unsigned
  Hosts:
    - 10.0.0.10:3389
Caps:
  # Required: Basic-authenticated clients carry no PAA token.
  TokenAuth: false
Ldap:
  Url: ldaps://ldap.example.com:636     # or ldap://...:389
  # StartTls: true                      # upgrade an ldap:// connection
  # CaFile: /etc/rdpgw/ldap-ca.pem      # instead of the system roots
  UserDnTemplate: uid={username},ou=people,dc=example,dc=com
  RequiredGroups:
    - cn=rdp,ou=groups,dc=example,dc=com
```

As environment variables:

```bash
RDPGW_SERVER__AUTHENTICATION=ldap
RDPGW_CAPS__TOKEN_AUTH=false
RDPGW_LDAP__URL=ldaps://ldap.example.com:636
RDPGW_LDAP__USER_DN_TEMPLATE=uid={username},ou=people,dc=example,dc=com
RDPGW_LDAP__REQUIRED_GROUPS=cn=rdp,ou=groups,dc=example,dc=com
```

`ldap` refuses to start with `TokenAuth: true` or `HostSelection: signed`,
which both need a PAA token. Use `unsigned` with an explicit `Hosts` list (or
`roundrobin`).

The environment loader splits values on spaces into lists, so DNs (the
template included) must not contain spaces; `RDPGW_LDAP__REQUIRED_GROUPS` takes
several DNs separated by spaces.

`ldap` replaces `local`: both are Basic auth, so they cannot be enabled
together. `ldap` can be stacked with `ntlm` or `kerberos`. It cannot share an
instance with `openid`, because an OpenID client sends no `Authorization`
header and would get the Basic challenge; run a second instance on its own
hostname instead.

## Behind a TLS-terminating proxy

Basic auth carries the password in every request, so it is refused with
`Tls: disable` unless you opt in:

```yaml
Server:
  Tls: disable
  TlsTerminatedByProxy: true
  TrustedProxies:
    - 10.0.0.0/8    # the proxy's addresses
```

rdpgw then accepts credentials only from a `TrustedProxies` peer that sends
`X-Forwarded-Proto: https`, and answers `403` to anything else without checking
the credentials. The same peers are trusted for `X-Forwarded-For`: the client
address, which the lockout keys on, is the rightmost entry that is not in
`TrustedProxies`. List every proxy hop in front of rdpgw, or the outermost one
becomes "the client" and all users share its lockout.

## Lockout

Basic auth attempts (`local` and `ldap`) are limited per client IP and per
username. Past the limit within `Window`, the key is refused for the given
duration without asking the backend, with the same `401` a wrong password gets.

```yaml
Lockout:
  IpMaxFailures: 10      # 0 disables
  IpDuration: 3600       # seconds
  UserMaxFailures: 5     # 0 disables
  UserDuration: 300
  Window: 900
```

These are the defaults. IPv6 clients are counted per /64. A successful login
clears the username's count but not the client IP's. The per-username lockout
lets anyone lock a user out of password login for `UserDuration`; keep it
short. The table holds at most 100000 keys; beyond that new keys are not
limited (and a log line says so) rather than locking everyone out.

Every attempt logs one line:

```
auth: result=failure method=basic reason=invalid_credentials user="alice" client_ip="203.0.113.7"
auth: result=lockout method=basic scope=user key="alice" duration=5m0s
auth: result=failure method=basic reason=locked_out user="alice" client_ip="198.51.100.2"
auth: result=success method=basic user="alice" client_ip="198.51.100.2"
```

`reason` is `invalid_credentials`, `access_denied` (valid password, not in a
required group) or `locked_out`. Passwords are never logged.

## Security considerations

- This is password-only: there is no second factor on the gateway. Limit it with
  `RequiredGroups`, keep Network Level Authentication on the hosts so the
  Windows login is a second password check, and prefer OpenID Connect where the
  client supports it.
- The gateway password is the directory password. Clients may store it.
- The directory's own lockout or rate limit (if any) still applies, and rdpgw's
  lockout runs before it.
- With `ldap://` and no `StartTls`, passwords cross the network to the LDAP
  server in clear text; rdpgw logs a warning at startup.

## Testing against a real directory

`TestLDAPAuthenticateExternal` in `cmd/rdpgw/web` runs against any LDAP
server; see the test for the environment variables, for example with
[lldap](https://github.com/lldap/lldap) in a container.
