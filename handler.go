package ldapbasicauth

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

func (m *LDAPBasicAuth) promptForCredentials(w http.ResponseWriter, err error) (caddyauth.User, bool, error) {
	realm := m.Realm
	if realm == "" {
		realm = "restricted"
	}
	realm = strings.ReplaceAll(realm, `\`, `\\`)
	realm = strings.ReplaceAll(realm, `"`, `\"`)
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	return caddyauth.User{}, false, err
}

func (m *LDAPBasicAuth) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	logger := caddy.Log().Named("ldap_basic_auth")
	remoteAddr, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if remoteAddr == "" {
		return caddyauth.User{}, false, fmt.Errorf("Caddy-resolved client IP is unavailable")
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		logger.Warn("No or invalid Authorization header",
			zap.String("remote_addr", remoteAddr),
			zap.String("host", r.Host),
			zap.String("path", r.URL.Path))
		return m.promptForCredentials(w, nil)
	}
	if locked, until := m.checkRateLimit(remoteAddr); locked {
		logger.Warn("Too many failed attempts, IP is temporarily locked", zap.String("remote_addr", remoteAddr), zap.Time("locked_until", until))
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(until.Sub(time.Now()).Seconds())))
		return m.promptForCredentials(w, fmt.Errorf("client IP %s is temporarily rate limited until %s", remoteAddr, until.Format(time.RFC3339)))
	}
	if username == "" || password == "" || !utf8.ValidString(username) {
		logger.Warn("Empty or invalid UTF-8 username, or empty password", zap.String("remote_addr", remoteAddr))
		m.registerFailedAttempt(remoteAddr)
		return m.promptForCredentials(w, nil)
	}
	logger.Info("Attempting authentication", zap.String("user", username), zap.String("remote_addr", remoteAddr))
	if m.InsecureSkipVerify {
		logger.Warn("TLS certificate verification is disabled! This is insecure and should not be used in production.")
	}

	l, err := m.getConn()
	if err != nil {
		logger.Error("LDAP connection failed", zap.String("user", username), zap.Error(err))
		return caddyauth.User{}, false, fmt.Errorf("LDAP connection failed: %w", err)
	}
	if l == nil {
		return caddyauth.User{}, false, fmt.Errorf("LDAP connection returned nil")
	}
	discardConn := false
	defer func() {
		if discardConn {
			l.Close()
		} else {
			m.putConn(l)
		}
	}()

	userDN := fmt.Sprintf("%s=%s,%s", m.UserAttr, ldap.EscapeDN(username), m.BaseDN)
	if m.LDAPBindDN != "" {
		search := ldap.NewSearchRequest(m.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
			fmt.Sprintf("(%s=%s)", m.UserAttr, ldap.EscapeFilter(username)), []string{"dn"}, nil)
		result, searchErr := l.Search(search)
		if searchErr != nil {
			discardConn = true
			logger.Error("LDAP user search failed", zap.String("user", username), zap.Error(searchErr))
			return caddyauth.User{}, false, fmt.Errorf("LDAP user search failed: %w", searchErr)
		}
		if result == nil || len(result.Entries) != 1 {
			logger.Warn("LDAP user search did not return exactly one account", zap.String("user", username), zap.Int("matches", entryCount(result)))
			m.registerFailedAttempt(remoteAddr)
			return m.promptForCredentials(w, nil)
		}
		userDN = result.Entries[0].DN
	}
	authConn := l
	if m.LDAPBindDN != "" {
		authConn, err = m.newConn()
		if err != nil {
			logger.Error("LDAP authentication connection failed", zap.String("user", username), zap.Error(err))
			return caddyauth.User{}, false, fmt.Errorf("LDAP authentication connection failed: %w", err)
		}
		defer authConn.Close()
	}
	if err = authConn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			logger.Warn("LDAP bind rejected credentials", zap.String("user", username), zap.Error(err))
			m.registerFailedAttempt(remoteAddr)
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			return m.promptForCredentials(w, nil)
		}
		logger.Error("LDAP bind failed", zap.String("user", username), zap.Error(err))
		return caddyauth.User{}, false, fmt.Errorf("LDAP bind failed: %w", err)
	}
	logger.Debug("LDAP bind successful", zap.String("user", username))

	if m.GroupMembershipDN != "" {
		groupFilter := fmt.Sprintf("(%s=%s)", m.GroupMembershipAttr, ldap.EscapeFilter(userDN))
		logger.Debug("Preparing LDAP group membership search", zap.String("base", m.GroupMembershipDN), zap.String("filter", groupFilter), zap.String("userDN", userDN))
		groupSearch := ldap.NewSearchRequest(m.GroupMembershipDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			groupFilter, []string{"dn"}, nil)
		groupResult, groupErr := l.Search(groupSearch)
		if groupErr != nil {
			discardConn = true
			logger.Error("LDAP group search error", zap.String("user", username), zap.Error(groupErr))
			return caddyauth.User{}, false, fmt.Errorf("LDAP group search failed: %w", groupErr)
		}
		if groupResult == nil || len(groupResult.Entries) == 0 {
			logger.Info("User is not a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN), zap.String("filter", groupFilter))
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			m.registerFailedAttempt(remoteAddr)
			return m.promptForCredentials(w, nil)
		}
		logger.Debug("User is a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN), zap.String("filter", groupFilter))
	}

	m.resetRateLimit(remoteAddr)
	logger.Info("Authentication successful", zap.String("user", username), zap.String("remote_addr", remoteAddr))
	return caddyauth.User{ID: username}, true, nil
}

func entryCount(result *ldap.SearchResult) int {
	if result == nil {
		return 0
	}
	return len(result.Entries)
}
