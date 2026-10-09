package cache

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestCacheKeyUsesFullQuestionType(t *testing.T) {
	a := new(dns.Msg)
	a.SetQuestion("type.example.", dns.TypeA)
	b := a.Copy()
	b.Question[0].Qtype = dns.TypeCAA // 257 shares A's low byte.
	if getMsgKey(a) == getMsgKey(b) {
		t.Fatal("A and CAA query types collide in the cache")
	}
}

func TestNonINETQueryCannotReadOrOverwriteINETCache(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	q := new(dns.Msg)
	q.SetQuestion("class.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	rr, err := dns.NewRR("class.example. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{rr}
	if !saveRespToCache(getMsgKey(q), r, c.backend, 0) {
		t.Fatal("failed to store INET response")
	}
	q.Question[0].Qclass = dns.ClassCHAOS
	qCtx := query_context.NewContext(q)
	upstream := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		if qCtx.R() != nil {
			t.Fatal("CHAOS query received a cached INET response")
		}
		response := new(dns.Msg)
		response.SetReply(qCtx.Q())
		response.Rcode = dns.RcodeNameError
		qCtx.SetResponse(response)
		return nil
	})
	next := sequence.NewChainWalker([]*sequence.ChainNode{{E: upstream}}, nil)
	if err := c.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	q.Question[0].Qclass = dns.ClassINET
	cached, lazy := getRespFromCache(getMsgKey(q), c.backend, false, 5)
	if cached == nil || lazy || cached.Rcode != dns.RcodeSuccess || len(cached.Answer) != 1 {
		t.Fatal("CHAOS query overwrote the INET cache entry")
	}
}

func TestCacheDoesNotReuseINETKeyForOtherClasses(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("class.example.", dns.TypeA)
	inetKey := getMsgKey(q)
	if inetKey == "" {
		t.Fatal("INET queries should be cacheable")
	}
	for _, class := range []uint16{dns.ClassCHAOS, dns.ClassHESIOD, dns.ClassNONE, dns.ClassANY} {
		q.Question[0].Qclass = class
		if got := getMsgKey(q); got != "" && got == inetKey {
			t.Fatalf("class %d can reuse an INET cache entry", class)
		}
	}
}
