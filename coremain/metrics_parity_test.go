//go:build !mosdns_minimal

package coremain

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
)

// This fixture is shared with Rust and fixes the default process collector's
// metric names/types. The registry's process collector has no mosdns_ prefix.
func TestProcessMetricsSharedContract(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("shared process fixture covers Linux and macOS")
	}
	data, err := os.ReadFile("../tests/fixtures/process_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]map[string]string
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	wanted := fixture["unix"]
	if runtime.GOOS == "linux" {
		for name, kind := range fixture["linux"] {
			wanted[name] = kind
		}
	}
	m := NewTestMosdnsWithPlugins(nil)
	families, err := m.metricsReg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		kind, ok := wanted[family.GetName()]
		if !ok {
			continue
		}
		if family.GetType().String() != kind || len(family.GetMetric()) != 1 {
			t.Fatalf("%s: wrong type or sample count", family.GetName())
		}
		metric := family.GetMetric()[0]
		if len(metric.GetLabel()) != 0 {
			t.Fatalf("%s: unexpected process labels", family.GetName())
		}
		value := metric.GetGauge().GetValue()
		if kind == "COUNTER" {
			value = metric.GetCounter().GetValue()
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			t.Fatalf("%s: invalid value %v", family.GetName(), value)
		}
		delete(wanted, family.GetName())
	}
	if len(wanted) != 0 {
		t.Fatalf("missing default metrics: %v", wanted)
	}
}

func TestMetricsHTTPEndpointRetainsPrefixAndValues(t *testing.T) {
	m := NewTestMosdnsWithPlugins(nil)
	m.initHttpMux()
	c := metrics.NewCounter(metrics.CounterOpts{Name: "fixture_total", Help: "fixture requests", ConstLabels: metrics.Labels{"tag": "fixture"}})
	m.GetMetricsReg().MustRegister(c)
	c.Add(2)
	w := httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("metrics endpoint status/type: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	for _, line := range []string{"# HELP mosdns_fixture_total fixture requests\n", "# TYPE mosdns_fixture_total counter\n", "mosdns_fixture_total{tag=\"fixture\"} 2\n", "go_goroutines "} {
		if !strings.Contains(w.Body.String(), line) {
			t.Fatalf("missing %q in metrics endpoint", line)
		}
	}
}
