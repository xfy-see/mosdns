//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/transport"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func closeResourceConcurrently(t *testing.T, u Upstream) {
	t.Helper()
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- u.Close() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Close: %v", err)
		}
	}
}

func exchangeResourceQuery(t *testing.T, u Upstream, id uint16) {
	t.Helper()
	wire, q := dohHTTPTestQuery(t, id)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := u.ExchangeContext(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(reply)
	r := new(dns.Msg)
	if err = r.Unpack(*reply); err != nil || r.Id != q.Id || !r.Response || r.Question[0] != q.Question[0] {
		t.Fatalf("query failed before lifecycle check: %v, %v", r, err)
	}
}

func TestDoHIdleConnectionsCloseLifecycle(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			server, _ := dohHTTPTestServer(t, h2, 0)
			observer := new(contractObserver)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			u, err := NewUpstream(server.URL+"/dns-query", Opt{TLSConfig: &tls.Config{RootCAs: roots}, EventObserver: observer})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = u.Close() })
			exchangeResourceQuery(t, u, 10)
			exchangeResourceQuery(t, u, 11)
			observer.require(t, 1, 0)
			closeResourceConcurrently(t, u)
			deadline := time.Now().Add(time.Second)
			for observer.closed.Load() != 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			t.Logf("after Close: opened=%d closed=%d", observer.opened.Load(), observer.closed.Load())
			observer.require(t, 1, 1)
			runtime.KeepAlive(u)
		})
	}
}

func resourceQUICListener(t *testing.T, alpn string) (*quic.Listener, *tls.Config) {
	t.Helper()
	cert, err := utils.GenerateCertificate("localhost")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}

func resourceDoQServer(t *testing.T) (string, *tls.Config, <-chan *quic.Conn) {
	t.Helper()
	listener, clientTLS := resourceQUICListener(t, "doq")
	accepted := make(chan *quic.Conn, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		accepted <- conn
		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			q, _, err := dnsutils.ReadMsgFromTCP(stream)
			if err != nil {
				stream.CancelRead(0)
				_ = stream.Close()
				return
			}
			r := new(dns.Msg)
			r.SetReply(q)
			_, _ = dnsutils.WriteMsgToTCP(stream, r)
			_ = stream.Close()
			stream.CancelRead(0)
		}
	}()
	return listener.Addr().String(), clientTLS, accepted
}

func resourceHTTP3Server(t *testing.T) (string, *tls.Config, <-chan *quic.Conn) {
	t.Helper()
	listener, clientTLS := resourceQUICListener(t, "h3")
	accepted := make(chan *quic.Conn, 1)
	hs := &http3.Server{ConnContext: func(ctx context.Context, c *quic.Conn) context.Context { accepted <- c; return ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		q := new(dns.Msg)
		if err = q.Unpack(wire); err != nil {
			w.WriteHeader(400)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		wire, err = reply.Pack()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	})}
	done := make(chan error, 1)
	go func() { done <- hs.ServeListener(listener) }()
	t.Cleanup(func() {
		_ = hs.Close()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("HTTP3 test server did not stop")
		}
	})
	return listener.Addr().String(), clientTLS, accepted
}

func TestQUICSocketCloseLifecycle(t *testing.T) {
	for _, protocol := range []string{"doq", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var addr string
			var clientTLS *tls.Config
			var accepted <-chan *quic.Conn
			if protocol == "doq" {
				addr, clientTLS, accepted = resourceDoQServer(t)
			} else {
				addr, clientTLS, accepted = resourceHTTP3Server(t)
			}
			url := "doq://localhost"
			opt := Opt{DialAddr: addr, TLSConfig: clientTLS}
			if protocol == "h3" {
				url = "https://localhost/dns-query"
				opt.EnableHTTP3 = true
			}
			u, err := NewUpstream(url, opt)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = u.Close() })
			exchangeResourceQuery(t, u, 20)
			exchangeResourceQuery(t, u, 21)
			var conn *quic.Conn
			select {
			case conn = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("QUIC server did not observe client")
			}
			client := conn.RemoteAddr().(*net.UDPAddr)
			closeResourceConcurrently(t, u)
			wire, _ := dohHTTPTestQuery(t, 22)
			reply, exchangeErr := u.ExchangeContext(context.Background(), wire)
			if reply != nil {
				pool.ReleaseBuf(reply)
			}
			if !errors.Is(exchangeErr, transport.ErrClosedTransport) {
				t.Errorf("QUIC query accepted after Close: %v", exchangeErr)
			}
			rebound, err := net.ListenPacket("udp4", client.String())
			t.Logf("client UDP address after Close: %s, rebind error=%v", client, err)
			if err != nil {
				t.Errorf("owned UDP socket remained bound after Close: %v", err)
			} else {
				_ = rebound.Close()
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(time.Second):
				t.Error("peer connection remained open after Close")
			}
			runtime.KeepAlive(u)
		})
	}
}

func TestDoHCloseCancelsPendingRequests(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, callerCanceled := range []bool{false, true} {
			name := fmt.Sprintf("http2=%v/callerCanceled=%v", h2, callerCanceled)
			t.Run(name, func(t *testing.T) {
				entered := make(chan struct{})
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered)
					<-r.Context().Done()
				}))
				server.EnableHTTP2 = h2
				server.StartTLS()
				defer server.Close()
				observer := new(contractObserver)
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				u, err := NewUpstream(server.URL+"/dns-query", Opt{TLSConfig: &tls.Config{RootCAs: roots}, EventObserver: observer})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = u.Close() })
				wire, _ := dohHTTPTestQuery(t, 25)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				replied := make(chan error, 1)
				go func() {
					reply, err := u.ExchangeContext(ctx, wire)
					if reply != nil {
						pool.ReleaseBuf(reply)
					}
					replied <- err
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("pending DoH fixture did not receive request")
				}
				if callerCanceled {
					cancel()
					select {
					case err := <-replied:
						if !errors.Is(err, context.Canceled) {
							t.Errorf("caller cancellation changed: %v", err)
						}
					case <-time.After(time.Second):
						t.Fatal("caller did not return")
					}
				}
				closeResourceConcurrently(t, u)
				if !callerCanceled {
					select {
					case err := <-replied:
						if err == nil {
							t.Error("pending request succeeded despite Close")
						}
					case <-time.After(time.Second):
						t.Error("Close did not cancel pending HTTP request")
					}
				}
				observer.require(t, 1, 1)
				reply, err := u.ExchangeContext(context.Background(), wire)
				if reply != nil {
					pool.ReleaseBuf(reply)
				}
				if !errors.Is(err, transport.ErrClosedTransport) {
					t.Errorf("query accepted after Close: %v", err)
				}
			})
		}
	}
}

func TestDoHConstructorFailureClosesOwnedQUICSocket(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	qt := &quic.Transport{Conn: conn}
	owned := &ownedQUICSocket{transport: qt, conn: conn}
	t.Cleanup(func() { _ = owned.Close() })
	h3 := &http3.Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		return nil, errors.New("not dialed")
	}}
	u, err := newDoHWithOwnedTransport("https://invalid\x00host/dns-query", h3, owned, nil)
	if u != nil || err == nil {
		t.Fatalf("invalid constructor result: %v, %v", u, err)
	}
	rebound, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatalf("failed construction retained UDP socket: %v", err)
	}
	_ = rebound.Close()
	runtime.KeepAlive(owned)
}

func TestQUICOwnedSocketCloseBeforeDial(t *testing.T) {
	for _, scheme := range []string{"doq", "h3"} {
		t.Run(scheme, func(t *testing.T) {
			u, err := NewUpstream(scheme+"://127.0.0.1", Opt{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = u.Close() })
			owned := u.(*upstreamWithOwnedCloser).closer.(*ownedQUICSocket)
			addr := owned.conn.LocalAddr().String()
			closeResourceConcurrently(t, u)
			rebound, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Fatalf("undialed QUIC UDP socket remained bound: %v", err)
			}
			_ = rebound.Close()
			runtime.KeepAlive(u)
		})
	}
}
