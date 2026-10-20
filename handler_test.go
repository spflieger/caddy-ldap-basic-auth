package ldapbasicauth

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestLDAPConnectionFailureDoesNotLockOutClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()

	m := testAuthHandler(address)
	ip := "192.0.2.10"
	defer rateLimitMap.Delete(ip)
	for i := 0; i < 3; i++ {
		if _, authenticated, err := authenticate(t, m, ip, "password"); authenticated || err == nil {
			t.Fatalf("request %d: authenticated = %t, error = %v; want backend error", i+1, authenticated, err)
		}
	}
	if attempts := failedAttempts(ip); attempts != 0 {
		t.Fatalf("failed attempts = %d, want 0", attempts)
	}
}

func TestInvalidLDAPCredentialsStillCount(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					request, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					response := ber.NewSequence("LDAP response")
					response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value.(int64), "message ID"))
					bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "bind response")
					bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.LDAPResultInvalidCredentials, "result code"))
					bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
					bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic message"))
					response.AppendChild(bind)
					if _, err := conn.Write(response.Bytes()); err != nil {
						return
					}
				}
			}()
		}
	}()

	m := testAuthHandler(listener.Addr().String())
	ip := "192.0.2.11"
	defer rateLimitMap.Delete(ip)
	if _, authenticated, err := authenticate(t, m, ip, "password"); authenticated || err != nil {
		t.Fatalf("authenticated = %t, error = %v; want rejected credentials without backend error", authenticated, err)
	}
	if attempts := failedAttempts(ip); attempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", attempts)
	}
}

func TestEmptyPasswordStillCounts(t *testing.T) {
	m := testAuthHandler("127.0.0.1:1")
	ip := "192.0.2.12"
	defer rateLimitMap.Delete(ip)
	if _, authenticated, err := authenticate(t, m, ip, ""); authenticated || err != nil {
		t.Fatalf("authenticated = %t, error = %v; want empty password rejected without backend error", authenticated, err)
	}
	if attempts := failedAttempts(ip); attempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", attempts)
	}
}

func TestInvalidUTF8UsernameStillCountsAsFailedAttempt(t *testing.T) {
	m := testAuthHandler("127.0.0.1:1")
	ip := "192.0.2.13"
	defer rateLimitMap.Delete(ip)
	if _, authenticated, err := authenticateWithUsername(t, m, ip, string([]byte{0xff}), "password"); authenticated || err != nil {
		t.Fatalf("authenticated = %t, error = %v; want invalid UTF-8 username rejected", authenticated, err)
	}
	if attempts := failedAttempts(ip); attempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", attempts)
	}
}

func TestMissingCredentialsUsesConfiguredRealm(t *testing.T) {
	m := &LDAPBasicAuth{Realm: "Medes Login"}
	request := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	response := httptest.NewRecorder()
	_, authenticated, err := m.Authenticate(response, request)
	if err != nil || authenticated {
		t.Fatalf("authenticated = %t, error = %v; want an authentication challenge", authenticated, err)
	}
	if got, want := response.Header().Get("WWW-Authenticate"), `Basic realm="Medes Login"`; got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestAuthenticationUsesCaddyClientIP(t *testing.T) {
	const spoofedIP = "203.0.113.30"
	for _, tt := range []struct {
		name       string
		peerIP     string
		resolvedIP string
	}{
		{name: "direct IPv4", peerIP: "192.0.2.30"},
		{name: "direct IPv6", peerIP: "2001:db8::30"},
		{name: "Caddy-resolved proxy client", peerIP: "192.0.2.30", resolvedIP: "198.51.100.30"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wantIP := tt.peerIP
			if tt.resolvedIP != "" {
				wantIP = tt.resolvedIP
			}
			for _, ip := range []string{tt.peerIP, wantIP, spoofedIP} {
				rateLimitMap.Delete(ip)
				t.Cleanup(func() { rateLimitMap.Delete(ip) })
			}

			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			request.RemoteAddr = net.JoinHostPort(tt.peerIP, "12345")
			request.SetBasicAuth("alice", "")
			for _, header := range []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"} {
				request.Header.Set(header, spoofedIP)
			}
			request = prepareTestRequest(request)
			if tt.resolvedIP != "" {
				caddyhttp.SetVar(request.Context(), caddyhttp.ClientIPVarKey, tt.resolvedIP)
			}

			m := testAuthHandler("127.0.0.1:1")
			if _, authenticated, err := m.Authenticate(httptest.NewRecorder(), request); authenticated || err != nil {
				t.Fatalf("authenticated = %t, error = %v; want empty password rejected", authenticated, err)
			}
			if attempts := failedAttempts(wantIP); attempts != 1 {
				t.Fatalf("failed attempts for resolved IP %q = %d, want 1", wantIP, attempts)
			}
			if attempts := failedAttempts(spoofedIP); attempts != 0 {
				t.Fatalf("failed attempts for spoofed IP = %d, want 0", attempts)
			}
			if tt.peerIP != wantIP && failedAttempts(tt.peerIP) != 0 {
				t.Fatal("failure counted against proxy IP instead of Caddy-resolved client IP")
			}
		})
	}
}

func TestAuthenticationRequiresCaddyClientIP(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare bool
		value   any
	}{
		{name: "unprepared request"},
		{name: "missing variable", prepare: true},
		{name: "empty variable", prepare: true, value: ""},
		{name: "wrong variable type", prepare: true, value: 123},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			request.RemoteAddr = "192.0.2.31:12345"
			request.Header.Set("X-Forwarded-For", "203.0.113.31")
			request.SetBasicAuth("alice", "")
			if tt.prepare {
				request = prepareTestRequest(request)
				caddyhttp.SetVar(request.Context(), caddyhttp.ClientIPVarKey, tt.value)
			}

			m := testAuthHandler("127.0.0.1:1")
			_, authenticated, err := m.Authenticate(httptest.NewRecorder(), request)
			if authenticated || err == nil || err.Error() != "Caddy-resolved client IP is unavailable" {
				t.Fatalf("authenticated = %t, error = %v; want missing client IP error", authenticated, err)
			}
		})
	}
}

func testAuthHandler(address string) *LDAPBasicAuth {
	return &LDAPBasicAuth{
		LDAPServer:              address,
		BaseDN:                  "ou=users,dc=example,dc=com",
		UserAttr:                "uid",
		PoolSize:                1,
		RateLimitMaxAttempts:    2,
		RateLimitWindowSeconds:  60,
		RateLimitLockoutSeconds: 60,
	}
}

func authenticate(t *testing.T, m *LDAPBasicAuth, ip, password string) (caddyauth.User, bool, error) {
	return authenticateWithUsername(t, m, ip, "alice", password)
}

func authenticateWithUsername(t *testing.T, m *LDAPBasicAuth, ip, username, password string) (caddyauth.User, bool, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = net.JoinHostPort(ip, "12345")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	return m.Authenticate(httptest.NewRecorder(), prepareTestRequest(request))
}

func prepareTestRequest(request *http.Request) *http.Request {
	return caddyhttp.PrepareRequest(request, caddy.NewReplacer(), nil, &caddyhttp.Server{})
}

func failedAttempts(ip string) int {
	value, ok := rateLimitMap.Load(ip)
	if !ok {
		return 0
	}
	return value.(*rateLimitInfo).Attempts
}
