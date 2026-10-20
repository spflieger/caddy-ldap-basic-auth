package ldapbasicauth

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/go-ldap/ldap/v3"
)

const (
	defaultLDAPRequestTimeout = 10 * time.Second
	maxLDAPRequestTimeout     = 5 * time.Minute
)

type LDAPBasicAuth struct {
	LDAPServer          string `json:"ldap_server"`
	Realm               string `json:"realm,omitempty"`
	BaseDN              string `json:"base_dn"`
	UserAttr            string `json:"user_attr"`
	LDAPBindDN          string `json:"ldap_bind_dn,omitempty"`
	LDAPBindPassword    string `json:"ldap_bind_password,omitempty"`
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
			var err error
			switch d.Val() {
			case "realm":
				m.Realm, err = singleArgument(d)
			case "ldap_server":
				m.LDAPServer, err = singleArgument(d)
			case "base_dn":
				m.BaseDN, err = singleArgument(d)
			case "user_attr":
				m.UserAttr, err = singleArgument(d)
			case "ldap_bind_dn":
				m.LDAPBindDN, err = singleArgument(d)
			case "ldap_bind_password":
				m.LDAPBindPassword, err = singleArgument(d)
			case "group_membership_dn":
				m.GroupMembershipDN, err = singleArgument(d)
			case "group_membership_attr":
				m.GroupMembershipAttr, err = singleArgument(d)
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
				m.PoolSize, err = positiveIntArgument(d)
			case "ldap_request_timeout":
				m.LDAPRequestTimeout, err = singleArgument(d)
				if err == nil {
					if _, timeoutErr := m.requestTimeout(); timeoutErr != nil {
						err = d.Errf("%v", timeoutErr)
					}
				}
			case "rate_limit_max_attempts":
				m.RateLimitMaxAttempts, err = positiveIntArgument(d)
			case "rate_limit_window_seconds":
				m.RateLimitWindowSeconds, err = positiveIntArgument(d)
			case "rate_limit_lockout_seconds":
				m.RateLimitLockoutSeconds, err = positiveIntArgument(d)
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
			if err != nil {
				return err
			}
		}
	}

	m.applyDefaults()
	return nil
}

func singleArgument(d *caddyfile.Dispenser) (string, error) {
	var value string
	if !d.AllArgs(&value) {
		return "", d.ArgErr()
	}
	return value, nil
}

func positiveIntArgument(d *caddyfile.Dispenser) (int, error) {
	directive := d.Val()
	value, err := singleArgument(d)
	if err != nil {
		return 0, err
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 {
		return 0, d.Errf("%s must be a positive integer, got %q", directive, value)
	}
	return number, nil
}

func (m *LDAPBasicAuth) applyDefaults() {
	if m.Realm == "" {
		m.Realm = "restricted"
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
}

func (m *LDAPBasicAuth) Provision(caddy.Context) error {
	m.applyDefaults()
	return nil
}

func (m *LDAPBasicAuth) Validate() error {
	if strings.ContainsAny(m.Realm, "\r\n") {
		return fmt.Errorf("realm cannot contain carriage returns or newlines")
	}
	if m.LDAPServer == "" {
		return fmt.Errorf("ldap_server is required")
	}
	if m.BaseDN == "" {
		return fmt.Errorf("base_dn is required")
	}
	if _, err := ldap.ParseDN(m.BaseDN); err != nil {
		return fmt.Errorf("base_dn is not a valid LDAP distinguished name: %w", err)
	}
	if m.UserAttr == "" {
		return fmt.Errorf("user_attr is required")
	}
	if !validLDAPAttributeType(m.UserAttr) {
		return fmt.Errorf("user_attr must be a valid LDAP attribute type (RFC 4512 / RFC 4514): %q", m.UserAttr)
	}
	if m.GroupMembershipDN != "" {
		if _, err := ldap.ParseDN(m.GroupMembershipDN); err != nil {
			return fmt.Errorf("group_membership_dn is not a valid LDAP distinguished name: %w", err)
		}
	}
	if !validLDAPAttributeDescription(m.GroupMembershipAttr) {
		return fmt.Errorf("group_membership_attr must be a valid LDAP attribute description (RFC 4512): %q", m.GroupMembershipAttr)
	}
	if (m.LDAPBindDN == "") != (m.LDAPBindPassword == "") {
		return fmt.Errorf("ldap_bind_dn and ldap_bind_password must be configured together")
	}
	if m.LDAPBindDN != "" {
		if _, err := ldap.ParseDN(m.LDAPBindDN); err != nil {
			return fmt.Errorf("ldap_bind_dn is not a valid LDAP distinguished name: %w", err)
		}
	}
	if m.PoolSize < 1 || m.RateLimitMaxAttempts < 1 || m.RateLimitWindowSeconds < 1 || m.RateLimitLockoutSeconds < 1 {
		return fmt.Errorf("pool_size and rate limit values must be positive")
	}
	_, err := m.requestTimeout()
	return err
}

func validLDAPAttributeType(value string) bool {
	if isLDAPKeyString(value) {
		return true
	}
	return isLDAPNumericOID(value)
}

func validLDAPAttributeDescription(value string) bool {
	parts := strings.Split(value, ";")
	if !validLDAPAttributeType(parts[0]) {
		return false
	}
	for _, option := range parts[1:] {
		if option == "" {
			return false
		}
		for _, r := range option {
			if !isLDAPKeyChar(r) {
				return false
			}
		}
	}
	return true
}

func isLDAPNumericOID(value string) bool {
	arcs := strings.Split(value, ".")
	if len(arcs) < 2 {
		return false
	}
	for _, arc := range arcs {
		if arc == "" || (len(arc) > 1 && arc[0] == '0') {
			return false
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isLDAPKeyString(value string) bool {
	if value == "" || !isLDAPAlpha(rune(value[0])) {
		return false
	}
	for _, r := range value[1:] {
		if !isLDAPKeyChar(r) {
			return false
		}
	}
	return true
}

func isLDAPKeyChar(r rune) bool {
	return isLDAPAlpha(r) || (r >= '0' && r <= '9') || r == '-'
}

func isLDAPAlpha(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func (m *LDAPBasicAuth) Cleanup() error {
	if m.pool == nil {
		return nil
	}
	for {
		select {
		case conn := <-m.pool:
			if conn != nil {
				conn.Close()
			}
		default:
			return nil
		}
	}
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
