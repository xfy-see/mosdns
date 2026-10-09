// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"bytes"
	"context"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Both profiles must preserve DNS IDs, EDNS and TCP fallback after a TC reply.
func TestUDPTruncatedReplyFallsBackToTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var udpCalls, tcpCalls atomic.Int64
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	udpServer := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(udpReady) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		udpCalls.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		r.Truncated = true
		_ = w.WriteMsg(r)
	})}
	tcpServer := &dns.Server{Listener: listener, NotifyStartedFunc: func() { close(tcpReady) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		tcpCalls.Add(1)
		if q.Id != 0x1234 || q.IsEdns0() == nil || !q.IsEdns0().Do() {
			t.Errorf("TCP query metadata changed: %+v", q)
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.SetEdns0(1232, true)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.1")}}
		_ = w.WriteMsg(r)
	})}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	<-udpReady
	<-tcpReady
	t.Cleanup(func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() })
	u, err := NewUpstream("udp://"+listener.Addr().String(), Opt{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	q := new(dns.Msg)
	q.SetQuestion("fallback.example.", dns.TypeA)
	q.Id = 0x1234
	q.SetEdns0(1232, true)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(wire)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	replyWire, err := u.ExchangeContext(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(replyWire)
	r := new(dns.Msg)
	if err := r.Unpack(*replyWire); err != nil {
		t.Fatal(err)
	}
	if r.Id != q.Id || r.Truncated || r.IsEdns0() == nil || !r.IsEdns0().Do() || len(r.Answer) != 1 || r.Question[0] != q.Question[0] {
		t.Fatalf("fallback response changed: %+v", r)
	}
	if udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("fallback calls UDP=%d TCP=%d", udpCalls.Load(), tcpCalls.Load())
	}
	if !bytes.Equal(wire, before) {
		t.Fatal("upstream modified query buffer")
	}
}
