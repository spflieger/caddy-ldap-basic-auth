package ldapbasicauth

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/go-ldap/ldap/v3"
)

func TestLDAPRequestsTimeOutWhenServerDoesNotReply(t *testing.T) {
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
				io.Copy(io.Discard, conn)
			}()
		}
	}()

	m := &LDAPBasicAuth{LDAPServer: listener.Addr().String(), LDAPRequestTimeout: "1s"}
	requests := []struct {
		name string
		run  func(*ldap.Conn) error
	}{
		{"bind", func(conn *ldap.Conn) error {
			return conn.Bind("uid=alice,dc=example,dc=com", "password")
		}},
		{"search", func(conn *ldap.Conn) error {
			request := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil)
			_, err := conn.Search(request)
			return err
		}},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			conn, err := m.newConn()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			start := time.Now()
			if err := request.run(conn); !ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
				t.Fatalf("expected LDAP network timeout, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("request took %s despite a 1-second timeout", elapsed)
			}
		})
	}
}

func TestCaddyfileLDAPTimeout(t *testing.T) {
	m := new(LDAPBasicAuth)
	input := "ldap_basic_auth {\n ldap_request_timeout 2s\n}"
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatal(err)
	}
	if m.LDAPRequestTimeout != "2s" {
		t.Fatalf("LDAP timeout = %q, want 2s", m.LDAPRequestTimeout)
	}
}

func TestLDAPRequestTimeoutValidation(t *testing.T) {
	for _, test := range []struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		{value: "", want: 10 * time.Second},
		{value: "2s", want: 2 * time.Second},
		{value: "500ms", wantErr: true},
		{value: "6m", wantErr: true},
		{value: "2", wantErr: true},
	} {
		t.Run(test.value, func(t *testing.T) {
			m := &LDAPBasicAuth{LDAPRequestTimeout: test.value}
			got, err := m.requestTimeout()
			if (err != nil) != test.wantErr || (!test.wantErr && got != test.want) {
				t.Fatalf("requestTimeout() = %s, %v; want %s, error %t", got, err, test.want, test.wantErr)
			}
		})
	}
}
