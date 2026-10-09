// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	old "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func text(t *testing.T, r *Registry) string {
	t.Helper()
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	for _, family := range families {
		if _, err := MetricFamilyToText(&b, family); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}
func oldText(t *testing.T, r *old.Registry) string {
	t.Helper()
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	for _, family := range families {
		if _, err := expfmt.MetricFamilyToText(&b, family); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// The old client and formatter are test-only differential oracles. They do not
// appear in a normal go build dependency graph.
func TestTextMatchesOldOracle(t *testing.T) {
	for _, name := range []string{"latency", "查询-time"} {
		t.Run(name, func(t *testing.T) {
			r, previous := NewRegistry(), old.NewRegistry()
			wrapped, oldWrapped := WrapRegistererWithPrefix("mosdns_", WrapRegistererWithPrefix("fixture_", r)), old.WrapRegistererWithPrefix("mosdns_", old.WrapRegistererWithPrefix("fixture_", previous))
			for _, tag := range []string{"zeta", "引号\"\\\nvalue"} {
				labels := Labels{"tag": tag, "extra label": "值"}
				oldLabels := old.Labels{"tag": tag, "extra label": "值"}
				c := NewCounter(CounterOpts{Name: "query_total", Help: "count\\help\nnext", ConstLabels: labels})
				oc := old.NewCounter(old.CounterOpts{Name: "query_total", Help: "count\\help\nnext", ConstLabels: oldLabels})
				g := NewGauge(GaugeOpts{Name: "thread", Help: "threads", ConstLabels: labels})
				og := old.NewGauge(old.GaugeOpts{Name: "thread", Help: "threads", ConstLabels: oldLabels})
				h := NewHistogram(HistogramOpts{Name: name, Help: "histogram", ConstLabels: labels, Buckets: []float64{1, 5, 10}})
				oh := old.NewHistogram(old.HistogramOpts{Name: name, Help: "histogram", ConstLabels: oldLabels, Buckets: []float64{1, 5, 10}})
				wrapped.MustRegister(c, g, h)
				oldWrapped.MustRegister(oc, og, oh)
				for i := 0; i < 3; i++ {
					c.Inc()
					oc.Inc()
				}
				c.Add(0.25)
				oc.Add(0.25)
				g.Set(3)
				og.Set(3)
				g.Inc()
				og.Inc()
				g.Sub(1.25)
				og.Sub(1.25)
				g.Dec()
				og.Dec()
				for _, value := range []float64{-1, 0, .5, 1, 1.5, 5, 10, 11} {
					h.Observe(value)
					oh.Observe(value)
				}
				labels["tag"] = "mutated"
				oldLabels["tag"] = "mutated"
			}
			if got, want := text(t, r), oldText(t, previous); got != want {
				t.Fatalf("light/old text differ\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestColonLabelIsQuotedForValidScrape(t *testing.T) {
	r, previous := NewRegistry(), old.NewRegistry()
	r.MustRegister(NewCounter(CounterOpts{Name: "query:total", ConstLabels: Labels{"a:b": "value"}}))
	previous.MustRegister(old.NewCounter(old.CounterOpts{Name: "query:total", ConstLabels: old.Labels{"a:b": "value"}}))
	// The old formatter used metric-name validation for label names too. Its
	// unquoted colon label is rejected by its own UTF-8-aware text parser.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	if _, err := parser.TextToMetricFamilies(strings.NewReader(oldText(t, previous))); err == nil {
		t.Fatal("old colon-label formatter defect no longer reproduced")
	}
	got := text(t, r)
	if !strings.Contains(got, "query:total{\"a:b\"=\"value\"} 0\n") {
		t.Fatalf("metric colon or quoted label lost: %q", got)
	}
	parser = expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	if pair := families["query:total"].Metric[0].Label[0]; pair.GetName() != "a:b" || pair.GetValue() != "value" {
		t.Fatalf("parsed label changed: %v", pair)
	}
}

func TestRegistrationMatchesOldOracle(t *testing.T) {
	for _, test := range []struct {
		name          string
		first, second CounterOpts
		fail          bool
	}{
		{"duplicate", CounterOpts{Name: "a", Help: "help", ConstLabels: Labels{"tag": "one"}}, CounterOpts{Name: "a", Help: "help", ConstLabels: Labels{"tag": "one"}}, true},
		{"different series", CounterOpts{Name: "a", Help: "help", ConstLabels: Labels{"tag": "one"}}, CounterOpts{Name: "a", Help: "help", ConstLabels: Labels{"tag": "two"}}, false},
		{"help conflict", CounterOpts{Name: "a", Help: "help"}, CounterOpts{Name: "a", Help: "other"}, true},
		{"label conflict", CounterOpts{Name: "a", ConstLabels: Labels{"tag": "one"}}, CounterOpts{Name: "a", ConstLabels: Labels{"name": "two"}}, true},
		{"NUL label dimension collision", CounterOpts{Name: "a", ConstLabels: Labels{"a": "one", "b": "two"}}, CounterOpts{Name: "a", ConstLabels: Labels{"a\x00b": "three"}}, true},
		{"empty", CounterOpts{Name: "a"}, CounterOpts{}, true},
		{"invalid UTF8", CounterOpts{Name: "a"}, CounterOpts{Name: string([]byte{0xff})}, true},
		{"reserved label", CounterOpts{Name: "a"}, CounterOpts{Name: "b", ConstLabels: Labels{"__reserved": "value"}}, true},
		{"invalid label value", CounterOpts{Name: "a"}, CounterOpts{Name: "b", ConstLabels: Labels{"tag": string([]byte{0xff})}}, true},
		{"UTF8 names", CounterOpts{Name: "a"}, CounterOpts{Name: "查询", ConstLabels: Labels{"标签": "值"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, previous := NewRegistry(), old.NewRegistry()
			toOld := func(opts CounterOpts) old.CounterOpts {
				return old.CounterOpts{Name: opts.Name, Help: opts.Help, ConstLabels: old.Labels(opts.ConstLabels)}
			}
			r.MustRegister(NewCounter(test.first))
			previous.MustRegister(old.NewCounter(toOld(test.first)))
			err, oldErr := r.Register(NewCounter(test.second)), previous.Register(old.NewCounter(toOld(test.second)))
			if (err != nil) != test.fail || (oldErr != nil) != test.fail {
				t.Fatalf("registration error light=%v old=%v wantFail=%v", err, oldErr, test.fail)
			}
		})
	}
	// Invalid families were rejected by the old Gather. Reject them at registration
	// now so no partially invalid scrape can be emitted.
	for _, kind := range []string{"mixed type", "histogram suffix"} {
		t.Run(kind, func(t *testing.T) {
			r, previous := NewRegistry(), old.NewRegistry()
			var err, errorOld error
			if kind == "mixed type" {
				r.MustRegister(NewCounter(CounterOpts{Name: "a", ConstLabels: Labels{"tag": "one"}}))
				previous.MustRegister(old.NewCounter(old.CounterOpts{Name: "a", ConstLabels: old.Labels{"tag": "one"}}))
				err = r.Register(NewGauge(GaugeOpts{Name: "a", ConstLabels: Labels{"tag": "two"}}))
				errorOld = previous.Register(old.NewGauge(old.GaugeOpts{Name: "a", ConstLabels: old.Labels{"tag": "two"}}))
			} else {
				r.MustRegister(NewHistogram(HistogramOpts{Name: "a"}))
				previous.MustRegister(old.NewHistogram(old.HistogramOpts{Name: "a"}))
				err = r.Register(NewCounter(CounterOpts{Name: "a_sum"}))
				errorOld = previous.Register(old.NewCounter(old.CounterOpts{Name: "a_sum"}))
			}
			if errorOld == nil {
				_, errorOld = previous.Gather()
			}
			if err == nil || errorOld == nil {
				t.Fatalf("invalid family accepted: light=%v old=%v", err, errorOld)
			}
		})
	}
}

func TestDuplicatePrefixedCollectorRecoveryMatchesOldOracle(t *testing.T) {
	r, previous := NewRegistry(), old.NewRegistry()
	wrapped := WrapRegistererWithPrefix("cache_", WrapRegistererWithPrefix("mosdns_", r))
	oldWrapped := old.WrapRegistererWithPrefix("cache_", old.WrapRegistererWithPrefix("mosdns_", previous))
	first, second := NewCounter(CounterOpts{Name: "queries"}), NewCounter(CounterOpts{Name: "queries"})
	oldFirst, oldSecond := old.NewCounter(old.CounterOpts{Name: "queries"}), old.NewCounter(old.CounterOpts{Name: "queries"})
	wrapped.MustRegister(first)
	oldWrapped.MustRegister(oldFirst)
	var duplicate AlreadyRegisteredError
	var oldDuplicate old.AlreadyRegisteredError
	if err := wrapped.Register(second); !errors.As(err, &duplicate) {
		t.Fatalf("light duplicate type: %v", err)
	}
	if err := oldWrapped.Register(oldSecond); !errors.As(err, &oldDuplicate) {
		t.Fatalf("old duplicate type: %v", err)
	}
	if duplicate.ExistingCollector != first || oldDuplicate.ExistingCollector != oldFirst {
		t.Fatal("duplicate error concealed the existing original collector behind prefix wrappers")
	}
	// The previous registry unwraps only ExistingCollector; NewCollector retains
	// the wrapper that was actually passed into Registry.Register.
	if duplicate.NewCollector == second || oldDuplicate.NewCollector == oldSecond {
		t.Fatal("duplicate error discarded the attempted collector's prefix wrapper")
	}
	duplicate.ExistingCollector.(Counter).Inc()
	oldDuplicate.ExistingCollector.(old.Counter).Inc()
	if got, want := text(t, r), oldText(t, previous); got != want {
		t.Fatalf("recovered counter text: got %q want %q", got, want)
	}
}

func TestUnregisterPreservesDescriptorHistoryAndPrefix(t *testing.T) {
	r := NewRegistry()
	wrapped := WrapRegistererWithPrefix("cache_", WrapRegistererWithPrefix("mosdns_", r))
	c := NewCounter(CounterOpts{Name: "query_total", Help: "same"})
	wrapped.MustRegister(c)
	var already AlreadyRegisteredError
	if err := wrapped.Register(c); !errors.As(err, &already) {
		t.Fatalf("duplicate: %v", err)
	}
	if !wrapped.Unregister(c) || wrapped.Unregister(c) {
		t.Fatal("unregister did not remove one series")
	}
	if err := wrapped.Register(NewCounter(CounterOpts{Name: "query_total", Help: "changed"})); err == nil {
		t.Fatal("descriptor history lost")
	}
	wrapped.MustRegister(NewCounter(CounterOpts{Name: "query_total", Help: "same"}))
	if !strings.Contains(text(t, r), "mosdns_cache_query_total 0\n") {
		t.Fatal("nested prefix lost")
	}
	if err := wrapped.Register(NewCounter(CounterOpts{})); err == nil {
		t.Fatal("prefix concealed empty name")
	}
}

func TestConcurrentUpdatesAndSnapshots(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(CounterOpts{Name: "queries"})
	g := NewGauge(GaugeOpts{Name: "thread"})
	h := NewHistogram(HistogramOpts{Name: "latency", Buckets: []float64{1, 2, 5}})
	r.MustRegister(c, g, h)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Go(func() {
			for i := 0; i < 2000; i++ {
				c.Inc()
				g.Inc()
				h.Observe(1)
				g.Dec()
			}
		})
	}
	for i := 0; i < 100; i++ {
		families, err := r.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.Type != HistogramType {
				continue
			}
			snapshot := family.Metric[0].Histogram
			if snapshot.SampleSum != float64(snapshot.SampleCount) {
				t.Fatalf("torn histogram sum/count: %v", snapshot)
			}
			for _, bucket := range snapshot.Bucket {
				if bucket.CumulativeCount != snapshot.SampleCount {
					t.Fatalf("torn cumulative bucket: %v", snapshot)
				}
			}
		}
	}
	wait.Wait()
	families, _ := r.Gather()
	for _, family := range families {
		switch family.Name {
		case "queries":
			if family.Metric[0].Counter.Value != 16000 {
				t.Fatal("counter lost updates")
			}
		case "thread":
			if family.Metric[0].Gauge.Value != 0 {
				t.Fatal("gauge lost updates")
			}
		case "latency":
			if family.Metric[0].Histogram.SampleCount != 16000 {
				t.Fatal("histogram lost updates")
			}
		}
	}
}

func TestGatherDoesNotHoldRegistryLockDuringCallback(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(CounterOpts{Name: "callback_registered"})
	r.MustRegister(NewGaugeFunc(GaugeOpts{Name: "callback"}, func() float64 { _ = r.Register(c); return 1 }))
	if _, err := r.Gather(); err != nil {
		t.Fatal(err)
	}
	if got := text(t, r); !strings.Contains(got, "callback_registered 0\n") {
		t.Fatalf("callback registration lost: %s", got)
	}
}

func TestNonfiniteObservationsMatchOldOracle(t *testing.T) {
	r, previous := NewRegistry(), old.NewRegistry()
	h := NewHistogram(HistogramOpts{Name: "h", Buckets: []float64{1, 2}})
	oh := old.NewHistogram(old.HistogramOpts{Name: "h", Buckets: []float64{1, 2}})
	r.MustRegister(h)
	previous.MustRegister(oh)
	for _, v := range []float64{math.Inf(-1), math.Inf(1), math.NaN()} {
		h.Observe(v)
		oh.Observe(v)
	}
	if got, want := text(t, r), oldText(t, previous); got != want {
		t.Fatalf("special histogram differs:\n%s\n%s", got, want)
	}
}
