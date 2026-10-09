// SPDX-License-Identifier: GPL-3.0-or-later
package metrics_collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestSharedMetricsCollectorDescriptorsAndObservations(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/metrics_collector.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int      `json:"format_version"`
		Prefix  string   `json:"prefix"`
		Labels  []string `json:"label_names"`
		Names   []struct {
			Raw     string `json:"raw"`
			Escaped string `json:"escaped"`
		} `json:"names"`
		Bounds  []float64 `json:"latency_bounds"`
		Metrics []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Help string `json:"help"`
		} `json:"metrics"`
		Observations []struct {
			ElapsedUS   int64 `json:"elapsed_us"`
			Failed      bool  `json:"failed"`
			HasResponse bool  `json:"has_response"`
		} `json:"observations"`
		Expected struct {
			Queries float64  `json:"queries"`
			Errors  float64  `json:"errors"`
			Thread  float64  `json:"thread"`
			Count   uint64   `json:"latency_count"`
			Sum     float64  `json:"latency_sum_ms"`
			Buckets []uint64 `json:"bucket_counts"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Names) != 2 {
		t.Fatal("unexpected fixture")
	}
	synctest.Test(t, func(t *testing.T) {
		registry := metrics.NewRegistry()
		collectors := []*Collector{}
		for _, name := range f.Names {
			collector, err := NewCollector(metrics.WrapRegistererWithPrefix(f.Prefix, registry), name.Raw)
			if err != nil {
				t.Fatal(err)
			}
			collectors = append(collectors, collector)
		}
		for _, observation := range f.Observations {
			q := new(dns.Msg)
			q.SetQuestion("collector.example.", dns.TypeA)
			qCtx := query_context.NewContext(q)
			failure := errors.New("fixture failure")
			next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				time.Sleep(time.Duration(observation.ElapsedUS) * time.Microsecond)
				if observation.HasResponse {
					r := new(dns.Msg)
					r.SetReply(q)
					qCtx.SetResponse(r)
				}
				if observation.Failed {
					return failure
				}
				return nil
			})}}, nil)
			err := collectors[0].Exec(context.Background(), qCtx, next)
			if observation.Failed && err != failure || !observation.Failed && err != nil {
				t.Fatalf("unexpected exec error: %v", err)
			}
		}
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if len(families) != len(f.Metrics) {
			t.Fatalf("got %d families", len(families))
		}
		for _, expected := range f.Metrics {
			found := false
			for _, family := range families {
				name := f.Prefix + expected.Name
				if family.GetName() != name {
					continue
				}
				found = true
				if family.GetHelp() != expected.Help || strings.ToLower(family.GetType().String()) != expected.Kind || len(family.Metric) != 2 {
					t.Fatalf("descriptor mismatch: %s", family)
				}
				var rendered bytes.Buffer
				if _, err := metrics.MetricFamilyToText(&rendered, family); err != nil {
					t.Fatal(err)
				}
				text := rendered.String()
				if strings.Count(text, "# HELP "+name+" ") != 1 || strings.Count(text, "# TYPE "+name+" ") != 1 {
					t.Fatalf("duplicate headers: %s", text)
				}
				seen := map[string]bool{}
				for _, metric := range family.Metric {
					labels := []string{}
					for _, label := range metric.Label {
						labels = append(labels, label.GetName())
					}
					if !reflect.DeepEqual(labels, f.Labels) {
						t.Fatalf("incorrect labels: %s", metric)
					}
					label := metric.Label[0].GetValue()
					seen[label] = true
					isObserved := label == f.Names[0].Raw
					want := float64(0)
					if isObserved {
						switch expected.Name {
						case "query_total":
							want = f.Expected.Queries
						case "err_total":
							want = f.Expected.Errors
						case "thread":
							want = f.Expected.Thread
						}
					}
					switch expected.Kind {
					case "counter":
						if metric.Counter.GetValue() != want {
							t.Fatalf("counter mismatch: %s", metric)
						}
					case "gauge":
						if metric.Gauge.GetValue() != want {
							t.Fatalf("gauge mismatch: %s", metric)
						}
					case "histogram":
						count, sum := uint64(0), float64(0)
						if isObserved {
							count, sum = f.Expected.Count, f.Expected.Sum
						}
						if metric.Histogram.GetSampleCount() != count || metric.Histogram.GetSampleSum() != sum {
							t.Fatalf("duration must truncate before sum: %s", metric)
						}
						if len(metric.Histogram.Bucket) != len(f.Bounds) {
							t.Fatalf("wrong bounds: %s", metric)
						}
						for i, bucket := range metric.Histogram.Bucket {
							wantCount := uint64(0)
							if isObserved {
								wantCount = f.Expected.Buckets[i]
							}
							if bucket.GetUpperBound() != f.Bounds[i] || bucket.GetCumulativeCount() != wantCount {
								t.Fatalf("bucket mismatch: %s", bucket)
							}
						}
					}
				}
				for _, label := range f.Names {
					if !seen[label.Raw] || !strings.Contains(text, "name=\""+label.Escaped+"\"") {
						t.Fatalf("bad label escaping: %s", text)
					}
				}
			}
			if !found {
				t.Fatalf("missing family %s", expected.Name)
			}
		}
	})
}
