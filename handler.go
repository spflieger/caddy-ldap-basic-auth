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

	result, err := m.authenticateLDAP(username, password)
	if err != nil {
		logger.Error("LDAP authentication failed", zap.String("user", username), zap.Error(err))
		return caddyauth.User{}, false, err
	}
	if result != ldapAuthenticated {
		switch result {
		case ldapUserNotFound:
			logger.Warn("LDAP user search did not return exactly one account", zap.String("user", username))
		case ldapInvalidCredentials:
			logger.Warn("LDAP bind rejected credentials", zap.String("user", username))
		case ldapGroupDenied:
			logger.Info("User is not a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN))
		}
		m.registerFailedAttempt(remoteAddr)
		if result != ldapUserNotFound {
			timer := time.NewTimer(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
			}
		}
		return m.promptForCredentials(w, nil)
	}

	m.resetRateLimit(remoteAddr)
	logger.Info("Authentication successful", zap.String("user", username), zap.String("remote_addr", remoteAddr))
	return caddyauth.User{ID: username}, true, nil
}
