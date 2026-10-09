//go:build !mosdns_minimal

// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

package plugin

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type splitFixtureCase struct {
	Name      string   `json:"name"`
	QName     string   `json:"qname"`
	QType     uint16   `json:"qtype"`
	QClass    uint16   `json:"qclass"`
	RCode     int      `json:"rcode"`
	Addresses []string `json:"addresses"`
	TTL       uint32   `json:"ttl"`
	Repeat    int      `json:"repeat"`
}

func TestSharedCNSiteAndIPSplitFixture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate shared fixtures")
	}
	fixtureDir := filepath.Join(filepath.Dir(source), "../tests/fixtures")
	yamlData, err := os.ReadFile(filepath.Join(fixtureDir, "split.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := os.ReadFile(filepath.Join(fixtureDir, "split_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int                `json:"format_version"`
		Cases   []splitFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(jsonData, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatalf("unsupported fixture format %d", fixture.Version)
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var cfg coremain.Config
			if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
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
			seq := m.GetPlugin("main").(*sequence.Sequence)
			cached := m.GetPlugin("cached").(*cache.Cache)
			reg := metrics.NewRegistry()
			if err := cached.RegMetricsTo(reg); err != nil {
				t.Fatal(err)
			}
			for request := 0; request < c.Repeat; request++ {
				q := new(dns.Msg)
				q.SetQuestion(c.QName, c.QType)
				q.Id = uint16(100 + request)
				if c.QClass != 0 {
					q.Question[0].Qclass = c.QClass
				}
				qCtx := query_context.NewContext(q)
				qCtx.ServerMeta.ClientAddr = netip.MustParseAddr("127.0.0.1")
				qCtx.ServerMeta.ServerName = "main"
				if err := seq.Exec(context.Background(), qCtx); err != nil {
					t.Fatal(err)
				}
				r := qCtx.R()
				if r == nil {
					t.Fatal("response is nil")
				}
				if r.Id != q.Id || r.Rcode != c.RCode {
					t.Fatalf("request %d: ID/rcode = %d/%d, want %d/%d", request, r.Id, r.Rcode, q.Id, c.RCode)
				}
				addresses := make([]string, 0)
				for _, rr := range r.Answer {
					switch rr := rr.(type) {
					case *dns.A:
						addresses = append(addresses, rr.A.String())
					case *dns.AAAA:
						addresses = append(addresses, rr.AAAA.String())
					default:
						t.Fatalf("unexpected answer type %T", rr)
					}
					if ttl := rr.Header().Ttl; ttl > c.TTL || c.TTL-ttl > 1 {
						t.Errorf("request %d: TTL = %d, want %d or %d", request, ttl, c.TTL, c.TTL-1)
					}
					if rr.Header().Name != c.QName {
						t.Errorf("answer name = %q, want %q", rr.Header().Name, c.QName)
					}
				}
				if !reflect.DeepEqual(addresses, c.Addresses) {
					t.Errorf("request %d: addresses = %v, want %v", request, addresses, c.Addresses)
				}
				metrics, err := reg.Gather()
				if err != nil {
					t.Fatal(err)
				}
				for _, metric := range metrics {
					if metric.GetName() == "hit_total" && metric.Metric[0].Counter.GetValue() != float64(request) {
						t.Errorf("request %d: cache hits = %v, want %d", request, metric.Metric[0].Counter.GetValue(), request)
					}
				}
			}
		})
	}
}
