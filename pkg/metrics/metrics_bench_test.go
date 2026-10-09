// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

import (
	"testing"

	old "github.com/prometheus/client_golang/prometheus"
)

// These isolated update benchmarks compare the same metric operations and
// histogram boundaries. They do not measure DNS throughput or scrape latency.
func BenchmarkCounterInc(b *testing.B) {
	for _, implementation := range []string{"light", "old"} {
		for _, parallel := range []bool{false, true} {
			mode := "serial"
			if parallel {
				mode = "parallel"
			}
			b.Run(implementation+"/"+mode, func(b *testing.B) {
				var c interface{ Inc() }
				if implementation == "light" {
					c = NewCounter(CounterOpts{Name: "queries"})
				} else {
					c = old.NewCounter(old.CounterOpts{Name: "queries"})
				}
				b.ReportAllocs()
				b.ResetTimer()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							c.Inc()
						}
					})
				} else {
					for i := 0; i < b.N; i++ {
						c.Inc()
					}
				}
			})
		}
	}
}

func BenchmarkHistogramObserve(b *testing.B) {
	// These are metrics_collector's existing response-latency boundaries.
	bounds := []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000}
	values := [...]float64{.5, 1, 3, 10, 25, 50, 199, 500, 1500, 5000, 6000}
	for _, implementation := range []string{"light", "old"} {
		for _, parallel := range []bool{false, true} {
			mode := "serial"
			if parallel {
				mode = "parallel"
			}
			b.Run(implementation+"/"+mode, func(b *testing.B) {
				var h interface{ Observe(float64) }
				if implementation == "light" {
					h = NewHistogram(HistogramOpts{Name: "latency", Buckets: bounds})
				} else {
					h = old.NewHistogram(old.HistogramOpts{Name: "latency", Buckets: bounds})
				}
				b.ReportAllocs()
				b.ResetTimer()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						i := 0
						for pb.Next() {
							h.Observe(values[i%len(values)])
							i++
						}
					})
				} else {
					for i := 0; i < b.N; i++ {
						h.Observe(values[i%len(values)])
					}
				}
			})
		}
	}
}
