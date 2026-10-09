//go:build !mosdns_minimal

package profiles_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const protocolName = "profiles.test"

// These tests exercise encrypted protocols excluded from the minimal profile.
// All sockets are loopback, all CA/key material is ephemeral, and certificate
// validation stays enabled for both successful and rejected exchanges.
func protocolCertificate(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mosdns profile test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: protocolName},
		DNSNames: []string{protocolName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: private}},
		MinVersion:   tls.VersionTLS12,
	}, roots
}

type protocolObservation struct {
	query *dns.Msg
	meta  server.QueryMeta
}

type protocolHandler struct {
	seen  chan protocolObservation
	count atomic.Uint32
}

func (h *protocolHandler) Handle(_ context.Context, q *dns.Msg, meta server.QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	h.count.Add(1)
	h.seen <- protocolObservation{query: q.Copy(), meta: meta}
	r := new(dns.Msg)
	r.SetReply(q)
	r.SetEdns0(1232, true)
	r.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 61},
		AAAA: net.ParseIP("2001:db8::8"),
	}}
	b, err := pack(r)
	if err != nil {
		return nil
	}
	return b
}

func awaitProtocolStop(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("loopback protocol server did not stop")
	}
}

func startProtocolServer(t *testing.T, kind string, tlsConfig *tls.Config, h *protocolHandler) string {
	t.Helper()
	done := make(chan error, 1)
	switch kind {
	case "tls", "tls+pipeline":
		listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		go func() { done <- server.ServeTCP(listener, h, server.TCPServerOpts{IdleTimeout: time.Second}) }()
		t.Cleanup(func() { _ = listener.Close(); awaitProtocolStop(t, done) })
		return listener.Addr().String()
	case "quic", "doq":
		tlsConfig = tlsConfig.Clone()
		tlsConfig.NextProtos = []string{"doq"}
		listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() { done <- server.ServeDoQ(listener, h, server.DoQServerOpts{IdleTimeout: time.Second}) }()
		t.Cleanup(func() { _ = listener.Close(); awaitProtocolStop(t, done) })
		return listener.Addr().String()
	case "h3", "https_http3":
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dnsHandler := server.NewHttpHandler(h, server.HttpHandlerOpts{})
		s := &http3.Server{TLSConfig: tlsConfig, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.NegotiatedProtocol != http3.NextProtoH3 || r.URL.Path != "/dns-query" {
				t.Errorf("unexpected HTTP/3 protocol/path: proto=%s tls=%v path=%s", r.Proto, r.TLS, r.URL.Path)
			}
			dnsHandler.ServeHTTP(w, r)
		})}
		go func() { done <- s.Serve(packet) }()
		t.Cleanup(func() { _ = s.Close(); _ = packet.Close(); awaitProtocolStop(t, done) })
		return packet.LocalAddr().String()
	default:
		t.Fatalf("unknown fixture protocol %s", kind)
		return ""
	}
}

func TestFullProfileEncryptedDNSProtocols(t *testing.T) {
	for _, kind := range []string{"tls", "tls+pipeline", "quic", "doq", "h3", "https_http3"} {
		t.Run(kind, func(t *testing.T) {
			for _, trust := range []string{"trusted", "unknown_ca", "wrong_hostname"} {
				t.Run(trust, func(t *testing.T) {
					serverTLS, roots := protocolCertificate(t)
					h := &protocolHandler{seen: make(chan protocolObservation, 4)}
					addr := startProtocolServer(t, kind, serverTLS, h)
					clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
					if trust == "unknown_ca" {
						clientTLS.RootCAs = x509.NewCertPool()
					}
					if trust == "wrong_hostname" {
						clientTLS.ServerName = "wrong.profiles.test"
					}
					opt := upstream.Opt{DialAddr: addr, TLSConfig: clientTLS}
					scheme := kind
					path := ""
					if kind == "h3" || kind == "https_http3" {
						path = "/dns-query"
					}
					if kind == "https_http3" {
						scheme = "https"
						opt.EnableHTTP3 = true
					}
					u, err := upstream.NewUpstream(scheme+"://"+protocolName+path, opt)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = u.Close() })
					for _, id := range []uint16{0x1234, 0x5678} {
						q := new(dns.Msg)
						q.SetQuestion("answer.profiles.test.", dns.TypeAAAA)
						q.Id = id
						q.SetEdns0(1232, true)
						wire, err := q.Pack()
						if err != nil {
							t.Fatal(err)
						}
						original := bytes.Clone(wire)
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						raw, err := u.ExchangeContext(ctx, wire)
						cancel()
						if trust != "trusted" {
							if raw != nil {
								pool.ReleaseBuf(raw)
							}
							if err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
								t.Fatalf("%s did not fail certificate validation: %v", trust, err)
							}
							if got := h.count.Load(); got != 0 {
								t.Fatalf("rejected TLS peer received %d DNS queries", got)
							}
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						r := new(dns.Msg)
						err = r.Unpack(*raw)
						pool.ReleaseBuf(raw)
						if err != nil || !r.Response || r.Id != id || len(r.Question) != 1 || r.Question[0] != q.Question[0] || len(r.Answer) != 1 || r.IsEdns0() == nil || !r.IsEdns0().Do() {
							t.Fatalf("encrypted DNS response changed: %s err=%v", r, err)
						}
						a, ok := r.Answer[0].(*dns.AAAA)
						if !ok || !a.AAAA.Equal(net.ParseIP("2001:db8::8")) || a.Hdr.Ttl != 61 {
							t.Fatalf("unexpected answer %v", r.Answer)
						}
						if !bytes.Equal(wire, original) {
							t.Fatal("upstream modified caller's DNS message")
						}
						select {
						case seen := <-h.seen:
							if len(seen.query.Question) != 1 || seen.query.Question[0] != q.Question[0] || seen.query.IsEdns0() == nil || !seen.query.IsEdns0().Do() || seen.meta.ServerName != protocolName || !seen.meta.ClientAddr.IsLoopback() {
								t.Fatalf("server query or metadata changed: query=%s meta=%+v", seen.query, seen.meta)
							}
							if (kind == "quic" || kind == "doq" || path != "") && seen.query.Id != 0 {
								t.Fatalf("%s wire ID must be zero: %d", kind, seen.query.Id)
							}
						case <-time.After(time.Second):
							t.Fatal("DNS exchange completed without a server observation")
						}
					}
					if trust == "trusted" && h.count.Load() != 2 {
						t.Fatalf("want two successful queries, got %d", h.count.Load())
					}
					t.Logf("%s: validated %s certificate path", fmt.Sprint(kind), trust)
				})
			}
		})
	}
}
