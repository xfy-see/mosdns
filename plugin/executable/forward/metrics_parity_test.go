//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package fastforward

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestSharedForwardMetricDescriptors(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/forward_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FormatVersion int       `json:"format_version"`
		Prefix        string    `json:"prefix"`
		Tag           string    `json:"tag"`
		Upstream      string    `json:"upstream"`
		Labels        []string  `json:"label_names"`
		Bounds        []float64 `json:"latency_bounds"`
		Metrics       []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Help string `json:"help"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 {
		t.Fatalf("unexpected fixture version %d", fixture.FormatVersion)
	}
	forward, err := NewForward(&Args{Upstreams: []UpstreamConfig{{Tag: fixture.Upstream, Addr: "udp://127.0.0.1:1"}, {Addr: "udp://127.0.0.1:2"}}}, Opts{MetricsTag: fixture.Tag})
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	registry := metrics.NewRegistry()
	if err := forward.RegisterMetricsTo(metrics.WrapRegistererWithPrefix(fixture.Prefix, registry)); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != len(fixture.Metrics) {
		t.Fatalf("got %d families want %d", len(families), len(fixture.Metrics))
	}
	for _, expected := range fixture.Metrics {
		found := false
		for _, family := range families {
			if family.GetName() != fixture.Prefix+expected.Name {
				continue
			}
			found = true
			if strings.ToLower(family.GetType().String()) != expected.Kind || family.GetHelp() != expected.Help {
				t.Fatalf("descriptor mismatch: %s", family)
			}
			if len(family.Metric) != 1 {
				t.Fatalf("only tagged upstream is exported: %s", family)
			}
			metric := family.Metric[0]
			names := []string{}
			for _, label := range metric.Label {
				names = append(names, label.GetName())
				if label.GetName() == "tag" && label.GetValue() != fixture.Tag || label.GetName() == "upstream" && label.GetValue() != fixture.Upstream {
					t.Fatalf("wrong labels %s", metric)
				}
			}
			if !reflect.DeepEqual(names, fixture.Labels) {
				t.Fatalf("label names: got %v want %v", names, fixture.Labels)
			}
			if metric.GetCounter().GetValue() != 0 || metric.GetGauge().GetValue() != 0 {
				t.Fatalf("unexpected nonzero values: %s", metric)
			}
			if expected.Kind == "histogram" {
				bounds := []float64{}
				for _, bucket := range metric.Histogram.Bucket {
					bounds = append(bounds, bucket.GetUpperBound())
					if bucket.GetCumulativeCount() != 0 {
						t.Fatalf("unexpected histogram: %s", metric)
					}
				}
				if !reflect.DeepEqual(bounds, fixture.Bounds) || metric.Histogram.GetSampleCount() != 0 {
					t.Fatalf("histogram bounds got %v want %v", bounds, fixture.Bounds)
				}
			}
		}
		if !found {
			t.Fatalf("missing metric %s", expected.Name)
		}
	}
}

type backgroundFixtureUpstream struct {
	started  chan context.Context
	release  <-chan struct{}
	finished chan struct{}
}

func (u *backgroundFixtureUpstream) ExchangeContext(ctx context.Context, wire []byte) (*[]byte, error) {
	u.started <- ctx
	defer close(u.finished)
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-u.release:
	}
	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	response.SetReply(query)
	return pool.PackBuffer(response)
}
func (u *backgroundFixtureUpstream) Close() error { return nil }

func TestForwardBackgroundDeadlineSurvivesCallerCancellation(t *testing.T) {
	release := make(chan struct{})
	f := &Forward{args: &Args{Concurrent: 2}, logger: zap.NewNop()}
	stubs := []*backgroundFixtureUpstream{}
	for _, tag := range []string{"first", "second"} {
		u := &backgroundFixtureUpstream{started: make(chan context.Context, 1), release: release, finished: make(chan struct{})}
		wrapper := newWrapper(len(stubs), UpstreamConfig{Tag: tag}, "fixture")
		wrapper.u = u
		stubs = append(stubs, u)
		f.us = append(f.us, wrapper)
	}
	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := f.exchange(caller, query_context.NewContext(query), f.us); result <- err }()
	contexts := []context.Context{}
	for _, u := range stubs {
		select {
		case ctx := <-u.started:
			contexts = append(contexts, ctx)
		case <-time.After(time.Second):
			t.Fatal("upstream did not start")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("caller error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller did not stop")
	}
	for _, ctx := range contexts {
		if ctx.Err() != nil {
			t.Fatalf("background query canceled with caller: %v", ctx.Err())
		}
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 4*time.Second || remaining > 5*time.Second {
			t.Fatalf("unexpected independent deadline: %v %s", ok, remaining)
		}
	}
	close(release)
	for _, u := range stubs {
		select {
		case <-u.finished:
		case <-time.After(time.Second):
			t.Fatal("background query did not finish")
		}
	}
}
