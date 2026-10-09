//go:build !mosdns_minimal

package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type dohRequestObservation struct {
	proto int
	alpn  string
	sni   string
	addr  string
	err   error
}

func dohHTTPTestServer(t *testing.T, h2 bool, headerSize int) (*httptest.Server, <-chan dohRequestObservation) {
	t.Helper()
	observations := make(chan dohRequestObservation, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := dohRequestObservation{proto: r.ProtoMajor, alpn: r.TLS.NegotiatedProtocol, sni: r.TLS.ServerName, addr: r.RemoteAddr}
		wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		q := new(dns.Msg)
		if err == nil {
			err = q.Unpack(wire)
		}
		if err == nil && (q.Id != 0 || q.IsEdns0() == nil || !q.IsEdns0().Do()) {
			err = fmt.Errorf("DoH query did not retain zero wire ID and EDNS/DO")
		}
		observation.err = err
		observations <- observation
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.SetEdns0(q.IsEdns0().UDPSize(), true)
		reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		wire, err = reply.Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if headerSize > 0 {
			w.Header().Set("X-Pad", strings.Repeat("x", headerSize))
		}
		_, _ = w.Write(wire)
	}))
	server.EnableHTTP2 = h2
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, observations
}

func dohHTTPTestQuery(t *testing.T, id uint16) ([]byte, *dns.Msg) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("http2.test.", dns.TypeAAAA)
	query.Id = id
	query.SetEdns0(1232, true)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire, query
}

func dohHTTPTestUpstream(t *testing.T, server *httptest.Server) Upstream {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u, err := NewUpstream("https://example.com/dns-query", Opt{
		DialAddr:  server.Listener.Addr().String(),
		TLSConfig: &tls.Config{RootCAs: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func TestDoHHTTP2TLSAndHTTP1Fallback(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		t.Run(fmt.Sprintf("http2=%v", h2), func(t *testing.T) {
			server, observations := dohHTTPTestServer(t, h2, 0)
			u := dohHTTPTestUpstream(t, server)
			var firstAddr string
			for _, id := range []uint16{0x1234, 0x5678} {
				wire, query := dohHTTPTestQuery(t, id)
				original := bytes.Clone(wire)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				replyWire, err := u.ExchangeContext(ctx, wire)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				reply := new(dns.Msg)
				err = reply.Unpack(*replyWire)
				pool.ReleaseBuf(replyWire)
				if err != nil || reply.Id != id || reply.Question[0] != query.Question[0] || reply.IsEdns0() == nil || !reply.IsEdns0().Do() || len(reply.Answer) != 1 {
					t.Fatalf("DoH reply metadata changed: %+v, err=%v", reply, err)
				}
				if !bytes.Equal(wire, original) {
					t.Fatal("upstream modified caller's DNS query")
				}
				observation := <-observations
				wantProto, wantALPN := 1, "http/1.1"
				if h2 {
					wantProto, wantALPN = 2, "h2"
				}
				if observation.err != nil || observation.proto != wantProto || observation.alpn != wantALPN || observation.sni != "example.com" {
					t.Fatalf("TLS/ALPN/custom DialAddr changed: %+v", observation)
				}
				if firstAddr == "" {
					firstAddr = observation.addr
				} else if observation.addr != firstAddr {
					t.Fatalf("sequential DoH requests did not reuse their connection: %s, %s", firstAddr, observation.addr)
				}
			}
		})
	}
}

func TestDoHResponseHeaderLimit(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		for _, size := range []int{1024, 8192} {
			t.Run(fmt.Sprintf("http2=%v/bytes=%d", h2, size), func(t *testing.T) {
				server, observations := dohHTTPTestServer(t, h2, size)
				u := dohHTTPTestUpstream(t, server)
				wire, _ := dohHTTPTestQuery(t, 7)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reply, err := u.ExchangeContext(ctx, wire)
				if reply != nil {
					pool.ReleaseBuf(reply)
				}
				if (err != nil) != (size > 4096) {
					t.Fatalf("HTTP response header limit: size=%d err=%v", size, err)
				}
				observation := <-observations
				want := 1
				if h2 {
					want = 2
				}
				if observation.proto != want || observation.err != nil {
					t.Fatalf("test did not use requested HTTP protocol: %+v", observation)
				}
			})
		}
	}
}

func TestDoHRejectsUntrustedTLSCertificate(t *testing.T) {
	server, _ := dohHTTPTestServer(t, true, 0)
	u, err := NewUpstream("https://example.com/dns-query", Opt{DialAddr: server.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	wire, _ := dohHTTPTestQuery(t, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := u.ExchangeContext(ctx, wire)
	if reply != nil {
		pool.ReleaseBuf(reply)
	}
	if err == nil {
		t.Fatal("untrusted TLS certificate was accepted")
	}
}

func TestDoHHTTP2AdvertisesLimits(t *testing.T) {
	cert, err := utils.GenerateCertificate("h2-settings.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type settingsResult struct {
		settings map[uint16]uint32
		err      error
	}
	completed := make(chan settingsResult, 1)
	go func() {
		settings, err := func() (map[uint16]uint32, error) {
			conn, err := listener.Accept()
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			preface := make([]byte, 24)
			if _, err := io.ReadFull(conn, preface); err != nil {
				return nil, err
			}
			if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
				return nil, fmt.Errorf("unexpected HTTP/2 preface")
			}
			// Server SETTINGS; this fixture only inspects the client's SETTINGS,
			// then closes. The other tests exchange real requests with net/http.
			if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
				return nil, err
			}
			var header [9]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return nil, err
			}
			length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if header[3] != 4 || header[4] != 0 || binary.BigEndian.Uint32(header[5:]) != 0 || length%6 != 0 || length > 1024 {
				return nil, fmt.Errorf("invalid initial client SETTINGS frame")
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return nil, err
			}
			settings := make(map[uint16]uint32)
			for offset := 0; offset < length; offset += 6 {
				settings[binary.BigEndian.Uint16(payload[offset:])] = binary.BigEndian.Uint32(payload[offset+2:])
			}
			return settings, nil
		}()
		completed <- settingsResult{settings, err}
	}()
	u, err := NewUpstream("https://h2-settings.test/dns-query", Opt{DialAddr: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots}})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	wire, _ := dohHTTPTestQuery(t, 9)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, _ := u.ExchangeContext(ctx, wire)
	if reply != nil {
		pool.ReleaseBuf(reply)
	}
	_ = listener.Close()
	observed := <-completed
	if observed.err != nil {
		t.Fatal(observed.err)
	}
	if observed.settings[5] != 16*1024 || observed.settings[6] != 4*1024 {
		t.Fatalf("client HTTP/2 wire limits changed: %v", observed.settings)
	}
}

func TestDoHHTTP3AdvertisesOriginalHeaderLimit(t *testing.T) {
	cert, err := utils.GenerateCertificate("h3-settings.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type settingsResult struct {
		maxHeaderBytes uint64
		err            error
	}
	completed := make(chan settingsResult, 1)
	go func() {
		maxHeaderBytes, err := func() (uint64, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := listener.Accept(ctx)
			if err != nil {
				return 0, err
			}
			defer conn.CloseWithError(0, "settings observed")
			for {
				stream, err := conn.AcceptUniStream(ctx)
				if err != nil {
					return 0, err
				}
				_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(stream)
				streamType, err := quicvarint.Read(reader)
				if err != nil {
					return 0, err
				}
				if streamType != 0 { // Find the HTTP/3 control stream.
					stream.CancelRead(0)
					continue
				}
				frameType, err := quicvarint.Read(reader)
				if err != nil || frameType != 4 {
					return 0, fmt.Errorf("invalid HTTP/3 SETTINGS frame: type=%d err=%v", frameType, err)
				}
				length, err := quicvarint.Read(reader)
				if err != nil || length > 1024 {
					return 0, fmt.Errorf("invalid HTTP/3 SETTINGS length: %d err=%v", length, err)
				}
				payload := make([]byte, length)
				if _, err := io.ReadFull(reader, payload); err != nil {
					return 0, err
				}
				settings := bytes.NewReader(payload)
				for settings.Len() > 0 {
					id, err := quicvarint.Read(settings)
					if err != nil {
						return 0, err
					}
					value, err := quicvarint.Read(settings)
					if err != nil {
						return 0, err
					}
					if id == 6 { // SETTINGS_MAX_FIELD_SECTION_SIZE
						return value, nil
					}
				}
				return 0, fmt.Errorf("missing HTTP/3 field-section limit")
			}
		}()
		completed <- settingsResult{maxHeaderBytes, err}
	}()
	u, err := NewUpstream("https://h3-settings.test/dns-query", Opt{DialAddr: listener.Addr().String(), EnableHTTP3: true, TLSConfig: &tls.Config{RootCAs: roots}})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	wire, _ := dohHTTPTestQuery(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The fixture closes after receiving SETTINGS without serving a reply.
	// This checks the actual HTTP/3 constructor and negotiated QUIC settings.
	reply, _ := u.ExchangeContext(ctx, wire)
	if reply != nil {
		pool.ReleaseBuf(reply)
	}
	_ = listener.Close()
	observed := <-completed
	if observed.err != nil {
		t.Fatal(observed.err)
	}
	if observed.maxHeaderBytes != 4*1024 {
		t.Fatalf("HTTP/3 header limit changed: got %d, want 4096", observed.maxHeaderBytes)
	}
}
