//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
)

func TestSharedCacheMetricDescriptors(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/cache_metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FormatVersion int      `json:"format_version"`
		Prefix        string   `json:"prefix"`
		Labels        []string `json:"label_names"`
		Tags          []struct {
			Raw     string `json:"raw"`
			Escaped string `json:"escaped"`
		} `json:"tags"`
		Metrics []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Help string `json:"help"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 || len(fixture.Tags) != 2 {
		t.Fatalf("unexpected fixture version or tag count")
	}
	registry := metrics.NewRegistry()
	for _, tag := range fixture.Tags {
		cache := NewCache(&Args{}, Opts{MetricsTag: tag.Raw})
		defer cache.Close()
		if err := cache.RegMetricsTo(metrics.WrapRegistererWithPrefix(fixture.Prefix, registry)); err != nil {
			t.Fatal(err)
		}
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != len(fixture.Metrics) {
		t.Fatalf("got %d families, want %d", len(families), len(fixture.Metrics))
	}
	for _, expected := range fixture.Metrics {
		found := false
		for _, family := range families {
			name := fixture.Prefix + expected.Name
			if family.GetName() != name {
				continue
			}
			found = true
			if strings.ToLower(family.GetType().String()) != expected.Kind || family.GetHelp() != expected.Help {
				t.Fatalf("descriptor mismatch: %s", family)
			}
			if len(family.Metric) != len(fixture.Tags) {
				t.Fatalf("both cache instances must share one family: %s", family)
			}
			seen := map[string]bool{}
			for _, metric := range family.Metric {
				names := []string{}
				for _, label := range metric.Label {
					names = append(names, label.GetName())
					seen[label.GetValue()] = true
				}
				if !reflect.DeepEqual(names, fixture.Labels) || metric.GetCounter().GetValue() != 0 || metric.GetGauge().GetValue() != 0 {
					t.Fatalf("unexpected initial metric: %s", metric)
				}
			}
			var rendered bytes.Buffer
			if _, err := metrics.MetricFamilyToText(&rendered, family); err != nil {
				t.Fatal(err)
			}
			text := rendered.String()
			for _, tag := range fixture.Tags {
				if !seen[tag.Raw] || !strings.Contains(text, name+"{tag=\""+tag.Escaped+"\"} 0\n") {
					t.Fatalf("missing or incorrectly escaped tag %q: %s", tag.Raw, text)
				}
			}
			if strings.Count(text, "# HELP "+name+" ") != 1 || strings.Count(text, "# TYPE "+name+" ") != 1 {
				t.Fatalf("headers must be emitted once per family: %s", text)
			}
		}
		if !found {
			t.Fatalf("missing metric %s", expected.Name)
		}
	}
}
