// SPDX-License-Identifier: GPL-3.0-or-later
package reverselookup

import (
	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/miekg/dns"
	"net/netip"
	"testing"
	"time"
)

func TestReverseCacheShardsMappedAddressesAndClose(t *testing.T) {
	p := &ReverseLookup{args: &Args{Size: 1, TTL: 10, HandlePTR: true}, c: cache.New[key, string](cache.Opts{Size: 1})}
	defer p.Close()
	q := new(dns.Msg)
	q.SetQuestion("ecs.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		rr, err := dns.NewRR("ecs.example. 300 IN A " + ip)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	p.saveIPs(q, r)
	for _, rr := range r.Answer {
		if rr.Header().Ttl != 10 {
			t.Fatal("TTL cap differs")
		}
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "::ffff:192.0.2.1"} {
		addr := as16(netip.MustParseAddr(ip))
		if p.lookup(addr) != "ecs.example." {
			t.Fatalf("lookup %s", ip)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p.c.Store(key(as16(netip.MustParseAddr("192.0.2.9"))), "closed.test.", time.Now().Add(time.Minute))
	if p.lookup(as16(netip.MustParseAddr("192.0.2.9"))) != "closed.test." {
		t.Fatal("close disabled explicit operations")
	}
}

func TestReverseLookupEmptyAndMultiQuestionContract(t *testing.T) {
	p := &ReverseLookup{args: &Args{Size: 1, TTL: 10, HandlePTR: true}, c: cache.New[key, string](cache.Opts{Size: 1})}
	defer p.Close()
	if p.ResponsePTR(new(dns.Msg)) != nil {
		t.Fatal("empty question returned PTR")
	}
	for _, count := range []int{0, 2} {
		q := new(dns.Msg)
		for i := 0; i < count; i++ {
			q.Question = append(q.Question, dns.Question{Name: "question.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		}
		r := new(dns.Msg)
		r.SetReply(q)
		rr, err := dns.NewRR("rr-owner.test. 30 IN A 192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = []dns.RR{rr}
		p.saveIPs(q, r)
		if p.lookup(as16(netip.MustParseAddr("192.0.2.10"))) != "rr-owner.test." {
			t.Fatal("RR owner fallback differs")
		}
	}
}
