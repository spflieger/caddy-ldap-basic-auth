package ldapbasicauth

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type ldapAuthResult int

const (
	ldapUserNotFound ldapAuthResult = iota
	ldapInvalidCredentials
	ldapGroupDenied
	ldapAuthenticated
)

// authenticateLDAP owns the LDAP connections until all authentication work is done.
// Rejections are returned separately from backend errors so callers can apply policy.
func (m *LDAPBasicAuth) authenticateLDAP(username, password string) (ldapAuthResult, error) {
	conn, err := m.getConn()
	if err != nil {
		return ldapUserNotFound, fmt.Errorf("LDAP connection failed: %w", err)
	}
	if conn == nil {
		return ldapUserNotFound, fmt.Errorf("LDAP connection returned nil")
	}
	discardConn := false
	defer func() {
		if discardConn {
			conn.Close()
		} else {
			m.putConn(conn)
		}
	}()

	userDN, err := m.resolveUserDN(conn, username)
	if err != nil {
		discardConn = true
		return ldapUserNotFound, err
	}
	if userDN == "" {
		return ldapUserNotFound, nil
	}
	verified, err := m.verifyPassword(conn, userDN, password)
	if err != nil || !verified {
		return ldapInvalidCredentials, err
	}
	member, err := m.checkGroupMembership(conn, userDN)
	if err != nil {
		discardConn = true
		return ldapGroupDenied, err
	}
	if !member {
		return ldapGroupDenied, nil
	}
	return ldapAuthenticated, nil
}

func (m *LDAPBasicAuth) resolveUserDN(conn *ldap.Conn, username string) (string, error) {
	if m.LDAPBindDN == "" {
		return fmt.Sprintf("%s=%s,%s", m.UserAttr, ldap.EscapeDN(username), m.BaseDN), nil
	}
	search := ldap.NewSearchRequest(m.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		fmt.Sprintf("(%s=%s)", m.UserAttr, ldap.EscapeFilter(username)), []string{"dn"}, nil)
	result, err := conn.Search(search)
	if err != nil {
		return "", fmt.Errorf("LDAP user search failed: %w", err)
	}
	if result == nil || len(result.Entries) != 1 {
		return "", nil
	}
	return result.Entries[0].DN, nil
}

func (m *LDAPBasicAuth) verifyPassword(conn *ldap.Conn, userDN, password string) (bool, error) {
	if m.LDAPBindDN != "" {
		authConn, err := m.newConn()
		if err != nil {
			return false, fmt.Errorf("LDAP authentication connection failed: %w", err)
		}
		defer authConn.Close()
		conn = authConn
	}
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("LDAP bind failed: %w", err)
	}
	return true, nil
}

func (m *LDAPBasicAuth) checkGroupMembership(conn *ldap.Conn, userDN string) (bool, error) {
	if m.GroupMembershipDN == "" {
		return true, nil
	}
	filter := fmt.Sprintf("(%s=%s)", m.GroupMembershipAttr, ldap.EscapeFilter(userDN))
	search := ldap.NewSearchRequest(m.GroupMembershipDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"dn"}, nil)
	result, err := conn.Search(search)
	if err != nil {
		return false, fmt.Errorf("LDAP group search failed: %w", err)
	}
	return result != nil && len(result.Entries) > 0, nil
}
