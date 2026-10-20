package ldapbasicauth

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule((*LDAPBasicAuth)(nil))
	httpcaddyfile.RegisterHandlerDirective("ldap_basic_auth", parseCaddyfileHandler)
}

var (
	_ caddy.Module                = (*LDAPBasicAuth)(nil)
	_ caddy.Provisioner           = (*LDAPBasicAuth)(nil)
	_ caddy.Validator             = (*LDAPBasicAuth)(nil)
	_ caddy.CleanerUpper          = (*LDAPBasicAuth)(nil)
	_ caddyauth.Authenticator     = (*LDAPBasicAuth)(nil)
	_ caddyfile.Unmarshaler       = (*LDAPBasicAuth)(nil)
	_ caddyhttp.MiddlewareHandler = caddyauth.Authentication{}
)

func (*LDAPBasicAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.ldap",
		New: func() caddy.Module { return new(LDAPBasicAuth) },
	}
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(LDAPBasicAuth)
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"ldap": caddyconfig.JSON(m, nil),
		},
	}, nil
}
