//go:build !mosdns_minimal

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func testDoQTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"doq"}}, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"doq"}}
}

func TestDoQReleasesResponseBuffer(t *testing.T) {
	serverTLS, clientTLS := testDoQTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var payload atomic.Pointer[[]byte]
	released := make(chan struct{}, 1)
	originalRelease := pool.ReleaseBuf
	pool.ReleaseBuf = func(b *[]byte) {
		if b == payload.Load() {
			select {
			case released <- struct{}{}:
			default:
			}
		}
		originalRelease(b)
	}
	defer func() { pool.ReleaseBuf = originalRelease }()
	h := handlerFunc(func(_ context.Context, q *dns.Msg, _ QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		r := new(dns.Msg)
		r.SetReply(q)
		b, err := pack(r)
		if err != nil {
			return nil
		}
		payload.Store(b)
		return b
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServeDoQ(listener, h, DoQServerOpts{}) }()
	defer func() {
		listener.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	if _, err := dnsutils.WriteMsgToTCP(stream, q); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	r, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil || r == nil || r.Id != q.Id || !r.Response {
		t.Fatalf("invalid DoQ reply: %v, %v", r, err)
	}
	var trailer [1]byte
	if n, err := stream.Read(trailer[:]); n != 0 || err == nil {
		t.Fatalf("stream was not closed after reply: n=%d, err=%v", n, err)
	}
	select {
	case <-released:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DoQ response buffer was not returned to the pool after the stream completed")
	}
}
