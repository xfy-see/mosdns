// SPDX-License-Identifier: GPL-3.0-or-later
package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// These fixtures exercise the original event implementation without changing it.
type contractObserver struct{ opened, closed atomic.Int64 }

func (o *contractObserver) OnEvent(e Event) {
	if e == EventConnOpen {
		o.opened.Add(1)
	}
	if e == EventConnClose {
		o.closed.Add(1)
	}
}
func (o *contractObserver) require(t *testing.T, opened, closed int64) {
	t.Helper()
	if o.opened.Load() != opened || o.closed.Load() != closed {
		t.Fatalf("events=(%d,%d), want=(%d,%d)", o.opened.Load(), o.closed.Load(), opened, closed)
	}
	t.Logf("event_contract opened=%d closed=%d", opened, closed)
}

func TestEventObserverConcurrentCloseContract(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	observer := new(contractObserver)
	conn := wrapConn(left, observer)
	observer.require(t, 1, 0)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _ = conn.Close() }()
	}
	workers.Wait()
	observer.require(t, 1, 1)
	if wrapConn(nil, observer) != nil {
		t.Fatal("nil connection was wrapped")
	}
	observer.require(t, 1, 1)
}

func TestEventObserverTraditionalReuseContract(t *testing.T) {
	for protocol := range m {
		t.Run(protocol, func(t *testing.T) {
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				r := new(dns.Msg)
				r.SetReply(q)
				_ = w.WriteMsg(r)
			})
			addr, shutdown := m[protocol](t, handler)
			defer shutdown()
			observer := new(contractObserver)
			u, err := NewUpstream(protocol+"://"+addr, Opt{EventObserver: observer, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			q := new(dns.Msg)
			q.SetQuestion("events.example.", dns.TypeA)
			payload, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err = u.ExchangeContext(ctx, payload)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			opened := int64(1)
			// Original DoT wraps both its raw socket and its TLS connection.
			if protocol == "tls" {
				opened = 2
			}
			observer.require(t, opened, 0)
			if err = u.Close(); err != nil {
				t.Fatal(err)
			}
			if err = u.Close(); err != nil {
				t.Fatal(err)
			}
			observer.require(t, opened, opened)
		})
	}
}

func TestEventObserverFailedDialContract(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	observer := new(contractObserver)
	u, err := NewUpstream("tcp://"+addr, Opt{EventObserver: observer})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	q := new(dns.Msg)
	q.SetQuestion("failed-dial.example.", dns.TypeA)
	payload, _ := q.Pack()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = u.ExchangeContext(ctx, payload); err == nil {
		t.Fatal("dial unexpectedly succeeded")
	}
	observer.require(t, 0, 0)
}
