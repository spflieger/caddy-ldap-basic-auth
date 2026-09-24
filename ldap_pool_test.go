package ldapbasicauth

import (
	"net"
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
