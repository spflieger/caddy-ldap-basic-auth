package ldapbasicauth

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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
		if status := authStatus(t, m, ip); status != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status = %d, want 503", i+1, status)
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
	if status := authStatus(t, m, ip); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if attempts := failedAttempts(ip); attempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", attempts)
	}
}

func TestEmptyPasswordStillCounts(t *testing.T) {
	m := testAuthHandler("127.0.0.1:1")
	ip := "192.0.2.12"
	defer rateLimitMap.Delete(ip)
	if status := authStatusWithPassword(t, m, ip, ""); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if attempts := failedAttempts(ip); attempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", attempts)
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

func authStatus(t *testing.T, m *LDAPBasicAuth, ip string) int {
	return authStatusWithPassword(t, m, ip, "password")
}

func authStatusWithPassword(t *testing.T, m *LDAPBasicAuth, ip, password string) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = net.JoinHostPort(ip, "12345")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:"+password)))
	response := httptest.NewRecorder()
	if err := m.ServeHTTP(response, request, nil); err != nil {
		t.Fatal(err)
	}
	return response.Code
}

func failedAttempts(ip string) int {
	value, ok := rateLimitMap.Load(ip)
	if !ok {
		return 0
	}
	return value.(*rateLimitInfo).Attempts
}
