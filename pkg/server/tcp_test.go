package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
)

func TestTCPPipelinePreservesIDsAndMetadata(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	firstBlocked := make(chan struct{})
	firstDone := make(chan struct{})
	releaseFirst := make(chan struct{})
	defer close(releaseFirst)
	h := handlerFunc(func(ctx context.Context, q *dns.Msg, meta QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		if meta.FromUDP || !meta.ClientAddr.IsLoopback() || meta.ServerName != "" {
			t.Error("wrong TCP metadata")
		}
		if q.Id == 1 {
			defer close(firstDone)
			close(firstBlocked)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil
			}
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Compress = true
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120}, Target: "target.example.test."}}
		r.SetEdns0(1232, true)
		b, err := pack(r)
		if err != nil {
			t.Error(err)
		}
		return b
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServeTCP(l, h, TCPServerOpts{}) }()
	defer func() {
		l.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	q := new(dns.Msg)
	q.SetQuestion("alias.example.test.", dns.TypeA)
	q.Id = 1
	if _, err := dnsutils.WriteMsgToTCP(c, q); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstBlocked:
	case <-time.After(time.Second):
		t.Fatal("first query did not enter handler")
	}
	q.Id = 2
	if _, err := dnsutils.WriteMsgToTCP(c, q); err != nil {
		t.Fatal(err)
	}
	r, _, err := dnsutils.ReadMsgFromTCP(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Id != 2 || len(r.Answer) != 1 || r.Answer[0].(*dns.CNAME).Target != "target.example.test." || r.IsEdns0() == nil || !r.IsEdns0().Do() {
		t.Fatal("pipelined response lost its ID, compression target or EDNS metadata")
	}
	// A canceled connection must release an in-flight request waiting behind
	// a completed pipelined response.
	c.Close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("blocked pipelined query was not canceled")
	}
}

func TestTCPQueryCanceledOnClientDisconnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	started := make(chan struct{})
	canceled := make(chan error, 1)
	h := handlerFunc(func(ctx context.Context, _ *dns.Msg, _ QueryMeta, _ func(*dns.Msg) (*[]byte, error)) *[]byte {
		close(started)
		<-ctx.Done()
		canceled <- context.Cause(ctx)
		return nil
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServeTCP(l, h, TCPServerOpts{}) }()
	defer func() {
		l.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	if _, err := dnsutils.WriteMsgToTCP(c, q); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not enter handler")
	}
	c.Close()
	select {
	case cause := <-canceled:
		if cause != errConnectionCtxCanceled {
			t.Fatalf("wrong cancellation cause: %v", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnected query was not canceled")
	}
}
