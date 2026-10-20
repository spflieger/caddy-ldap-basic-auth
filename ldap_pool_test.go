package ldapbasicauth

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestPoolReusesConnectionsAfterAnonymousBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
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
					bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.LDAPResultSuccess, "result code"))
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

	m := &LDAPBasicAuth{LDAPServer: listener.Addr().String(), PoolSize: 1}
	m.initPool()
	if !m.anonymousBindSupported {
		t.Fatal("server accepted anonymous bind, but pooling was disabled")
	}
	for i := 0; i < 2; i++ {
		conn, err := m.getConn()
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Bind("uid=alice,ou=users,dc=example,dc=com", "password"); err != nil {
			t.Fatal(err)
		}
		m.putConn(conn)
		if got := len(m.pool); got != 1 {
			t.Fatalf("pooled connections = %d, want 1", got)
		}
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("accepted connections = %d, want 2 (probe and reused connection)", got)
	}
	(<-m.pool).Close()
}

func TestDirectUserConnectionsAreNotPooledWithoutAnonymousBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var accepted atomic.Int32
	var anonymousBinds atomic.Int32
	var userBinds atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				for {
					request, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					bindRequest := request.Children[1]
					dn, _ := bindRequest.Children[1].Value.(string)
					resultCode := ldap.LDAPResultSuccess
					if dn == "" {
						anonymousBinds.Add(1)
						resultCode = ldap.LDAPResultInvalidCredentials
					} else {
						userBinds.Add(1)
					}
					response := ber.NewSequence("LDAP response")
					response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value.(int64), "message ID"))
					bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "bind response")
					bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "result code"))
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

	m := &LDAPBasicAuth{LDAPServer: listener.Addr().String(), PoolSize: 1}
	for i := 0; i < 2; i++ {
		conn, err := m.getConn()
		if err != nil {
			t.Fatal(err)
		}
		userDN := "sAMAccountName=alice,ou=users,dc=example,dc=com"
		if err := conn.Bind(userDN, "password"); err != nil {
			t.Fatal(err)
		}
		m.putConn(conn)
		if got := len(m.pool); got != 0 {
			t.Fatalf("pooled connections = %d, want 0 when anonymous bind is denied", got)
		}
	}
	if got := accepted.Load(); got != 3 { // one anonymous capability probe plus two user connections
		t.Fatalf("accepted connections = %d, want 3", got)
	}
	if got := anonymousBinds.Load(); got != 1 {
		t.Fatalf("anonymous binds = %d, want 1 capability probe", got)
	}
	if got := userBinds.Load(); got != 2 {
		t.Fatalf("user binds = %d, want 2", got)
	}
}

func TestPoolReusesConnectionsWithSearchAccountBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var accepted atomic.Int32
	var binds atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				for {
					request, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					binds.Add(1)
					response := ber.NewSequence("LDAP response")
					response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value.(int64), "message ID"))
					bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "bind response")
					bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.LDAPResultSuccess, "result code"))
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

	m := &LDAPBasicAuth{
		LDAPServer:       listener.Addr().String(),
		LDAPBindDN:       "CN=reader,DC=example,DC=com",
		LDAPBindPassword: "test-secret",
		PoolSize:         1,
	}
	for i := 0; i < 2; i++ {
		conn, err := m.getConn()
		if err != nil {
			t.Fatal(err)
		}
		authConn, err := m.newConn()
		if err != nil {
			t.Fatal(err)
		}
		if err := authConn.Bind("sAMAccountName=alice,DC=example,DC=com", "password"); err != nil {
			t.Fatal(err)
		}
		authConn.Close()
		m.putConn(conn)
	}
	if got := accepted.Load(); got != 3 {
		t.Fatalf("accepted connections = %d, want 3 (one pooled search connection and two authentication connections)", got)
	}
	if got := binds.Load(); got != 3 {
		t.Fatalf("binds = %d, want 3 (search bind once and one user bind per request)", got)
	}
	(<-m.pool).Close()
}

func TestAuthenticationPoolModes(t *testing.T) {
	const (
		baseDN = "OU=Users,DC=example,DC=com"
		userDN = "CN=Alice,OU=Users,DC=example,DC=com"
	)
	tests := []struct {
		name                 string
		anonymousBindAllowed bool
		searchBind           bool
		wantConnections      int32
		wantAnonymousBinds   int32
	}{
		{name: "anonymous bind with direct user DN", anonymousBindAllowed: true, wantConnections: 2, wantAnonymousBinds: 4},
		{name: "no anonymous bind with direct user DN", anonymousBindAllowed: false, wantConnections: 3, wantAnonymousBinds: 1},
		{name: "search account with separate authentication connections", anonymousBindAllowed: false, searchBind: true, wantConnections: 3, wantAnonymousBinds: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestLDAPServer(t, tt.anonymousBindAllowed, userDN)
			m := &LDAPBasicAuth{
				LDAPServer:           server.listener.Addr().String(),
				BaseDN:               baseDN,
				UserAttr:             "sAMAccountName",
				PoolSize:             1,
				RateLimitMaxAttempts: 5,
			}
			if tt.searchBind {
				m.LDAPBindDN = "CN=ldap-reader,OU=Service,DC=example,DC=com"
				m.LDAPBindPassword = "reader-password"
			}
			for i := 0; i < 2; i++ {
				if status := authenticateTestRequest(t, m); status != http.StatusOK {
					t.Fatalf("request %d status = %d, want 200", i+1, status)
				}
			}

			if got := server.accepted.Load(); got != tt.wantConnections {
				t.Errorf("accepted connections = %d, want %d", got, tt.wantConnections)
			}
			if got := server.anonymousBinds.Load(); got != tt.wantAnonymousBinds {
				t.Errorf("anonymous binds = %d, want %d", got, tt.wantAnonymousBinds)
			}
			wantUserDN := userDN
			if !tt.searchBind {
				wantUserDN = "sAMAccountName=alice," + baseDN
			}
			if got := server.countBind(wantUserDN); got != 2 {
				t.Errorf("binds as constructed/found user DN = %d, want 2", got)
			}
			if tt.searchBind {
				if got := server.countBind(m.LDAPBindDN); got != 1 {
					t.Errorf("search-account binds = %d, want 1", got)
				}
				if got := server.searches.Load(); got != 2 {
					t.Errorf("user searches = %d, want 2", got)
				}
			} else if got := server.searches.Load(); got != 0 {
				t.Errorf("user searches = %d, want 0 for direct-DN mode", got)
			}
		})
	}
}

func TestUnicodeAndPunctuationUsernameInDirectBindDN(t *testing.T) {
	username := "Jöhn,Ops+1"
	baseDN := "DC=example,DC=com"
	wantDN := `sAMAccountName=Jöhn\,Ops\+1,` + baseDN
	if _, err := ldap.ParseDN(wantDN); err != nil {
		t.Fatalf("expected escaped DN to parse: %v", err)
	}
	server := newTestLDAPServer(t, false, wantDN)
	m := &LDAPBasicAuth{
		LDAPServer:              server.listener.Addr().String(),
		BaseDN:                  baseDN,
		UserAttr:                "sAMAccountName",
		PoolSize:                1,
		RateLimitMaxAttempts:    5,
		RateLimitWindowSeconds:  60,
		RateLimitLockoutSeconds: 60,
	}
	user, authenticated, err := authenticateWithUsername(t, m, "192.0.2.21", username, "password")
	if err != nil || !authenticated {
		t.Fatalf("authenticated = %t, error = %v; want successful authentication", authenticated, err)
	}
	if user.ID != username {
		t.Fatalf("user ID = %q, want %q", user.ID, username)
	}
	if got := server.countBind(wantDN); got != 1 {
		t.Fatalf("binds using escaped DN %q = %d, want 1", wantDN, got)
	}
}

func TestUnicodeAndPunctuationUsernameInSearchFilter(t *testing.T) {
	username := "Jöhn*(Ops)\\1"
	userDN := "CN=Jöhn,OU=Users,DC=example,DC=com"
	server := newTestLDAPServer(t, false, userDN)
	m := &LDAPBasicAuth{
		LDAPServer:              server.listener.Addr().String(),
		BaseDN:                  "DC=example,DC=com",
		UserAttr:                "sAMAccountName",
		LDAPBindDN:              "CN=reader,DC=example,DC=com",
		LDAPBindPassword:        "reader-password",
		PoolSize:                1,
		RateLimitMaxAttempts:    5,
		RateLimitWindowSeconds:  60,
		RateLimitLockoutSeconds: 60,
	}
	_, authenticated, err := authenticateWithUsername(t, m, "192.0.2.22", username, "password")
	if err != nil || !authenticated {
		t.Fatalf("authenticated = %t, error = %v; want successful authentication", authenticated, err)
	}
	server.mu.Lock()
	gotAttribute, gotValue := server.searchAttribute, server.searchValue
	server.mu.Unlock()
	if gotAttribute != "sAMAccountName" || gotValue != username {
		t.Fatalf("LDAP search assertion = (%q=%q), want (%q=%q)", gotAttribute, gotValue, "sAMAccountName", username)
	}
}

func authenticateTestRequest(t *testing.T, m *LDAPBasicAuth) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = net.JoinHostPort("192.0.2.20", "12345")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:password")))
	user, authenticated, err := m.Authenticate(httptest.NewRecorder(), prepareTestRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !authenticated {
		return http.StatusUnauthorized
	}
	if user.ID != "alice" {
		t.Fatalf("authenticated user ID = %q, want alice", user.ID)
	}
	return http.StatusOK
}

type testLDAPServer struct {
	listener        net.Listener
	allowAnonymous  bool
	userDN          string
	accepted        atomic.Int32
	anonymousBinds  atomic.Int32
	searches        atomic.Int32
	mu              sync.Mutex
	binds           map[string]int
	searchAttribute string
	searchValue     string
	searchBindDN    string
	bindResults     map[string]uint16
	searchEntries   map[string]int
	searchResults   map[string]uint16
}

func newTestLDAPServer(t *testing.T, allowAnonymous bool, userDN string) *testLDAPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testLDAPServer{listener: listener, allowAnonymous: allowAnonymous, userDN: userDN, binds: make(map[string]int)}
	t.Cleanup(func() { listener.Close() })
	go server.serve()
	return server
}

func (s *testLDAPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		go s.serveConn(conn)
	}
}

func (s *testLDAPServer) serveConn(conn net.Conn) {
	defer conn.Close()
	boundDN := ""
	for {
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		messageID := request.Children[0].Value.(int64)
		operation := request.Children[1]
		response := ber.NewSequence("LDAP response")
		response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "message ID"))
		switch operation.Tag {
		case ldap.ApplicationBindRequest:
			dn, _ := operation.Children[1].Value.(string)
			resultCode := ldap.LDAPResultSuccess
			if dn == "" {
				s.anonymousBinds.Add(1)
				if !s.allowAnonymous {
					resultCode = ldap.LDAPResultInvalidCredentials
				}
			} else {
				s.mu.Lock()
				s.binds[dn]++
				resultCode = int(s.bindResults[dn])
				s.mu.Unlock()
				if resultCode == ldap.LDAPResultSuccess {
					boundDN = dn
				}
			}
			bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "bind response")
			bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "result code"))
			bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
			bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic message"))
			response.AppendChild(bind)
		case ldap.ApplicationSearchRequest:
			s.searches.Add(1)
			baseDN, _ := operation.Children[0].Value.(string)
			s.mu.Lock()
			s.searchBindDN = boundDN
			entries, configured := s.searchEntries[baseDN]
			if !configured {
				entries = 1
			}
			resultCode := s.searchResults[baseDN]
			s.mu.Unlock()
			if len(operation.Children) > 6 {
				filter := operation.Children[6]
				if filter.Tag == 3 && len(filter.Children) == 2 {
					s.mu.Lock()
					s.searchAttribute, _ = filter.Children[0].Value.(string)
					s.searchValue, _ = filter.Children[1].Value.(string)
					s.mu.Unlock()
				}
			}
			if boundDN == "" {
				return
			}
			if resultCode == ldap.LDAPResultSuccess {
				for i := 0; i < entries; i++ {
					entryResponse := ber.NewSequence("LDAP search entry")
					entryResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "message ID"))
					entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "search entry")
					entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.userDN, "object name"))
					entry.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
					entryResponse.AppendChild(entry)
					if _, err := conn.Write(entryResponse.Bytes()); err != nil {
						return
					}
				}
			}
			response = ber.NewSequence("LDAP search result")
			response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "message ID"))
			done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "search done")
			done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "result code"))
			done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
			done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic message"))
			response.AppendChild(done)
		default:
			return
		}
		if _, err := conn.Write(response.Bytes()); err != nil {
			return
		}
	}
}

func (s *testLDAPServer) countBind(dn string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds[dn]
}
