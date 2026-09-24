package ldapbasicauth

import (
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/go-ldap/ldap/v3"
)

const (
	defaultLDAPRequestTimeout = 10 * time.Second
	maxLDAPRequestTimeout     = 5 * time.Minute
)

type LDAPBasicAuth struct {
	LDAPServer          string `json:"ldap_server"`
	BaseDN              string `json:"base_dn"`
	UserAttr            string `json:"user_attr"`
	GroupMembershipDN   string `json:"group_membership_dn"`
	GroupMembershipAttr string `json:"group_membership_attr,omitempty"`
	UseLDAPS            bool   `json:"use_ldaps,omitempty"`
	InsecureSkipVerify  bool   `json:"insecure_skip_verify,omitempty"`
	PoolSize            int    `json:"pool_size,omitempty"`
	LDAPRequestTimeout  string `json:"ldap_request_timeout,omitempty"`

	RateLimitMaxAttempts    int `json:"rate_limit_max_attempts,omitempty"`
	RateLimitWindowSeconds  int `json:"rate_limit_window_seconds,omitempty"`
	RateLimitLockoutSeconds int `json:"rate_limit_lockout_seconds,omitempty"`

	poolOnce sync.Once
	pool     chan *ldap.Conn

	anonymousBindSupported bool
}

func (m *LDAPBasicAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "ldap_server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LDAPServer = d.Val()
			case "base_dn":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BaseDN = d.Val()
			case "user_attr":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.UserAttr = d.Val()
			case "group_membership_dn":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GroupMembershipDN = d.Val()
			case "group_membership_attr":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GroupMembershipAttr = d.Val()
			case "use_ldaps":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.UseLDAPS = true
			case "insecure_skip_verify":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.InsecureSkipVerify = true
			case "pool_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var size int
				_, err := fmt.Sscanf(d.Val(), "%d", &size)
				if err != nil || size < 1 {
					return d.Errf("invalid pool_size value: %s", d.Val())
				}
				m.PoolSize = size
			case "ldap_request_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LDAPRequestTimeout = d.Val()
				if _, err := m.requestTimeout(); err != nil {
					return d.Errf("%v", err)
				}
			case "rate_limit_max_attempts":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_max_attempts: %s", d.Val())
				}
				m.RateLimitMaxAttempts = v
			case "rate_limit_window_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_window_seconds: %s", d.Val())
				}
				m.RateLimitWindowSeconds = v
			case "rate_limit_lockout_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_lockout_seconds: %s", d.Val())
				}
				m.RateLimitLockoutSeconds = v
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	if m.GroupMembershipAttr == "" {
		m.GroupMembershipAttr = "member"
	}
	if m.PoolSize == 0 {
		m.PoolSize = 5
	}
	if m.RateLimitMaxAttempts == 0 {
		m.RateLimitMaxAttempts = 5
	}
	if m.RateLimitWindowSeconds == 0 {
		m.RateLimitWindowSeconds = 60
	}
	if m.RateLimitLockoutSeconds == 0 {
		m.RateLimitLockoutSeconds = 300
	}

	return nil
}

func (m *LDAPBasicAuth) requestTimeout() (time.Duration, error) {
	if m.LDAPRequestTimeout == "" {
		return defaultLDAPRequestTimeout, nil
	}
	timeout, err := time.ParseDuration(m.LDAPRequestTimeout)
	if err != nil || timeout < time.Second || timeout > maxLDAPRequestTimeout {
		return 0, fmt.Errorf("ldap_request_timeout must be between 1s and 5m")
	}
	return timeout, nil
}
