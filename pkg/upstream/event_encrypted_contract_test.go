//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEventObserverFailedTLSHandshakeContract(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()
	observer := new(contractObserver)
	u, err := NewUpstream("tls://"+l.Addr().String(), Opt{EventObserver: observer, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	q := new(dns.Msg)
	q.SetQuestion("failed-tls.example.", dns.TypeA)
	payload, _ := q.Pack()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = u.ExchangeContext(ctx, payload); err == nil {
		t.Fatal("TLS handshake unexpectedly succeeded")
	}
	observer.require(t, 1, 1)
}
func TestEventObserverDoHCloseContract(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		name := "http1"
		if http2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload []byte
				var err error
				if r.Method == http.MethodGet {
					payload, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				} else {
					payload, err = io.ReadAll(r.Body)
				}
				if err != nil {
					t.Error(err)
					return
				}
				q := new(dns.Msg)
				if err := q.Unpack(payload); err != nil {
					t.Error(err)
					return
				}
				response := new(dns.Msg)
				response.SetReply(q)
				payload, err = response.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(payload)
			}))
			s.EnableHTTP2 = http2
			s.StartTLS()
			defer s.Close()
			observer := new(contractObserver)
			u, err := NewUpstream(s.URL+"/dns-query", Opt{EventObserver: observer, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			q := new(dns.Msg)
			q.SetQuestion("doh-events.example.", dns.TypeA)
			payload, _ := q.Pack()
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err := u.ExchangeContext(ctx, payload)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			observer.require(t, 1, 0)
			u.Close()
			deadline := time.Now().Add(time.Second)
			for observer.closed.Load() != 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			observer.require(t, 1, 1)
		})
	}
}
