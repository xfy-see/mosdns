package profiles

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
)

var siteOnlyTestID atomic.Uint64

func siteOnlyMock(t *testing.T, address, text string, requests *atomic.Uint64) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		requests.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		question := q.Question[0]
		if strings.HasPrefix(question.Name, "missing.") {
			r.Rcode = dns.RcodeNameError
			r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 60}}
		} else {
			h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: question.Qclass, Ttl: 60}
			switch question.Qtype {
			case dns.TypeA:
				r.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP(address).To4()}}
			case dns.TypeAAAA:
				r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::" + text)}}
			case dns.TypeTXT:
				r.Answer = []dns.RR{&dns.TXT{Hdr: h, Txt: []string{text}}}
			}
		}
		_ = w.WriteMsg(r)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		_ = pc.Close()
		t.Fatalf("mock start: %v", err)
	case <-time.After(3 * time.Second):
		_ = pc.Close()
		t.Fatal("mock readiness timeout")
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("mock shutdown timeout")
		}
	})
	return pc.LocalAddr().String()
}

// Both compiled profiles exercise the same current site-only sequence. A
// counting executable stands in for the privileged netlink operation here;
// actual nftset insertions are covered separately on the target router.
func TestSiteOnlyBranchCacheAndFinalization(t *testing.T) {
	var cnCalls, foreignCalls, finalizeCalls atomic.Uint64
	cn := siteOnlyMock(t, "198.18.0.1", "1", &cnCalls)
	foreign := siteOnlyMock(t, "203.0.113.2", "2", &foreignCalls)
	finalizeType := fmt.Sprintf("test_profile_finalize_%d", siteOnlyTestID.Add(1))
	sequence.MustRegExecQuickSetup(finalizeType, func(sequence.BQ, string) (any, error) {
		return sequence.ExecutableFunc(func(context.Context, *query_context.Context) error { finalizeCalls.Add(1); return nil }), nil
	})
	input := fmt.Sprintf(`log: {level: error}
plugins:
- tag: cn_site
  type: domain_set
  args:
    exps: ['domain:cn.test', 'full:only.test', 'regexp:^regex[0-9]+\.test$', 'keyword:cnkeyword']
- tag: cached
  type: cache
  args: {size: 1024, lazy_cache_ttl: 0}
- tag: cn_forward
  type: forward
  args: {upstreams: [{addr: '%s'}]}
- tag: foreign_forward
  type: forward
  args: {upstreams: [{addr: '%s'}]}
- tag: finalize
  type: sequence
  args:
  - {matches: 'qname $cn_site', exec: '%s'}
  - {exec: accept}
- tag: resolve_cn
  type: sequence
  args:
  - {exec: '$cn_forward'}
  - {exec: 'goto finalize'}
- tag: main
  type: sequence
  args:
  - {exec: '$cached'}
  - {matches: has_resp, exec: 'goto finalize'}
  - {matches: 'qname $cn_site', exec: 'goto resolve_cn'}
  - {exec: '$foreign_forward'}
  - {exec: 'goto finalize'}
`, cn, foreign, finalizeType)
	var cfg coremain.Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatal(err)
	}
	m, err := coremain.NewMosdns(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	main := m.GetPlugin("main").(*sequence.Sequence)
	cases := []struct {
		name   string
		typ    uint16
		cn, nx bool
	}{
		{"www.cn.test.", dns.TypeA, true, false},
		{"www.cn.test.", dns.TypeAAAA, true, false},
		{"www.cn.test.", dns.TypeTXT, true, false},
		{"only.test.", dns.TypeA, true, false},
		{"regex123.test.", dns.TypeA, true, false},
		{"www.cnkeyword.test.", dns.TypeA, true, false},
		{"www.cn.test.evil.", dns.TypeA, false, false},
		{"x.only.test.", dns.TypeAAAA, false, false},
		{"foreign.test.", dns.TypeA, false, false},
		{"foreign.test.", dns.TypeAAAA, false, false},
		{"missing.foreign.test.", dns.TypeA, false, true},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%s-%d", tc.name, tc.typ), func(t *testing.T) {
			beforeCN, beforeForeign, beforeFinalize := cnCalls.Load(), foreignCalls.Load(), finalizeCalls.Load()
			for repeat := 0; repeat < 2; repeat++ {
				q := new(dns.Msg)
				q.SetQuestion(tc.name, tc.typ)
				q.Id = uint16(1000 + i*2 + repeat)
				ctx := query_context.NewContext(q)
				deadline, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := main.Exec(deadline, ctx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				r := ctx.R()
				if r == nil || r.Id != q.Id || len(r.Question) != 1 || r.Question[0] != q.Question[0] {
					t.Fatalf("response identity: %v", r)
				}
				if tc.nx {
					if r.Rcode != dns.RcodeNameError || len(r.Ns) != 1 || r.Ns[0].Header().Rrtype != dns.TypeSOA {
						t.Fatalf("negative response: %v", r)
					}
				} else {
					if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
						t.Fatalf("positive response: %v", r)
					}
					rr := r.Answer[0]
					if rr.Header().Name != tc.name || rr.Header().Rrtype != tc.typ || rr.Header().Class != dns.ClassINET || rr.Header().Ttl > 60 || rr.Header().Ttl < 59 {
						t.Fatalf("answer header: %v", rr)
					}
					branch := "2"
					if tc.cn {
						branch = "1"
					}
					switch v := rr.(type) {
					case *dns.A:
						want := "203.0.113.2"
						if tc.cn {
							want = "198.18.0.1"
						}
						if v.A.String() != want {
							t.Fatalf("A=%v, want %s", v.A, want)
						}
					case *dns.AAAA:
						if v.AAAA.String() != "2001:db8::"+branch {
							t.Fatalf("AAAA=%v", v.AAAA)
						}
					case *dns.TXT:
						if len(v.Txt) != 1 || v.Txt[0] != branch {
							t.Fatalf("TXT=%v", v.Txt)
						}
					}
				}
			}
			wantCN, wantForeign, wantFinalize := uint64(0), uint64(1), uint64(0)
			if tc.cn {
				wantCN, wantForeign, wantFinalize = 1, 0, 2
			}
			if cnCalls.Load()-beforeCN != wantCN || foreignCalls.Load()-beforeForeign != wantForeign || finalizeCalls.Load()-beforeFinalize != wantFinalize {
				t.Fatalf("upstream/finalize increments=%d/%d/%d, want %d/%d/%d", cnCalls.Load()-beforeCN, foreignCalls.Load()-beforeForeign, finalizeCalls.Load()-beforeFinalize, wantCN, wantForeign, wantFinalize)
			}
		})
	}
}
