// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

import (
	"runtime"
	rmetrics "runtime/metrics"
	"sync"
	"time"
)

// functionMetric can omit an unavailable OS sample without hiding business metrics.
type functionMetric struct {
	base
	read func() (float64, bool)
}

func (f *functionMetric) Snapshot() *Metric {
	v, ok := f.read()
	if !ok {
		return nil
	}
	if f.desc.Type == CounterType {
		return &Metric{Counter: &Value{v}}
	}
	return &Metric{Gauge: &Value{v}}
}
func registerFunction(r Registerer, name, help string, kind MetricType, fn func() (float64, bool)) {
	r.MustRegister(&functionMetric{base: base{descriptor(Opts{Name: name, Help: help}, kind)}, read: fn})
}

type memorySnapshot struct {
	mu    sync.Mutex
	at    time.Time
	stats runtime.MemStats
}

func (m *memorySnapshot) read() runtime.MemStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.at) >= 100*time.Millisecond {
		runtime.ReadMemStats(&m.stats)
		m.at = time.Now()
	}
	return m.stats
}

// RegisterDefaults retains useful Go/process samples using the standard library.
// OS counters that cannot be read are omitted, never replaced with invented zeros.
func RegisterDefaults(r Registerer) {
	r.MustRegister(NewGaugeFunc(GaugeOpts{Name: "go_goroutines", Help: "Number of goroutines that currently exist."}, func() float64 { return float64(runtime.NumGoroutine()) }))
	r.MustRegister(NewGaugeFunc(GaugeOpts{Name: "go_threads", Help: "Number of OS threads created."}, func() float64 { n, _ := runtime.ThreadCreateProfile(nil); return float64(n) }))
	r.MustRegister(NewGaugeFunc(GaugeOpts{Name: "go_info", Help: "Information about the Go environment.", ConstLabels: Labels{"version": runtime.Version()}}, func() float64 { return 1 }))
	r.MustRegister(NewGaugeFunc(GaugeOpts{Name: "go_sched_gomaxprocs_threads", Help: "The current runtime.GOMAXPROCS setting."}, func() float64 { return float64(runtime.GOMAXPROCS(0)) }))
	memory := new(memorySnapshot)
	fields := []struct {
		name, help string
		kind       MetricType
		value      func(runtime.MemStats) float64
	}{
		{"alloc_bytes", "Number of bytes allocated and still in use.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.Alloc) }},
		{"alloc_bytes_total", "Total number of bytes allocated, even if freed.", CounterType, func(s runtime.MemStats) float64 { return float64(s.TotalAlloc) }},
		{"sys_bytes", "Number of bytes obtained from system.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.Sys) }},
		{"mallocs_total", "Total number of mallocs.", CounterType, func(s runtime.MemStats) float64 { return float64(s.Mallocs) }},
		{"frees_total", "Total number of frees.", CounterType, func(s runtime.MemStats) float64 { return float64(s.Frees) }},
		{"heap_alloc_bytes", "Number of heap bytes allocated and still in use.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapAlloc) }},
		{"heap_sys_bytes", "Number of heap bytes obtained from system.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapSys) }},
		{"heap_idle_bytes", "Number of heap bytes waiting to be used.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapIdle) }},
		{"heap_inuse_bytes", "Number of heap bytes that are in use.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapInuse) }},
		{"heap_released_bytes", "Number of heap bytes released to OS.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapReleased) }},
		{"heap_objects", "Number of allocated objects.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.HeapObjects) }},
		{"stack_inuse_bytes", "Number of bytes in use by the stack allocator.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.StackInuse) }},
		{"stack_sys_bytes", "Number of bytes obtained from system for stack allocator.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.StackSys) }},
		{"mspan_inuse_bytes", "Number of bytes in use by mspan structures.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.MSpanInuse) }},
		{"mspan_sys_bytes", "Number of bytes used for mspan structures obtained from system.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.MSpanSys) }},
		{"mcache_inuse_bytes", "Number of bytes in use by mcache structures.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.MCacheInuse) }},
		{"mcache_sys_bytes", "Number of bytes used for mcache structures obtained from system.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.MCacheSys) }},
		{"buck_hash_sys_bytes", "Number of bytes used by the profiling bucket hash table.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.BuckHashSys) }},
		{"gc_sys_bytes", "Number of bytes used for garbage collection system metadata.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.GCSys) }},
		{"other_sys_bytes", "Number of bytes used for other system allocations.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.OtherSys) }},
		{"next_gc_bytes", "Number of heap bytes when next garbage collection will take place.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.NextGC) }},
		{"last_gc_time_seconds", "Number of seconds since 1970 of last garbage collection.", GaugeType, func(s runtime.MemStats) float64 { return float64(s.LastGC) / 1e9 }},
		{"gc_cpu_fraction", "The fraction of this program's available CPU time used by the GC since the program started.", GaugeType, func(s runtime.MemStats) float64 { return s.GCCPUFraction }},
	}
	for _, field := range fields {
		registerFunction(r, "go_memstats_"+field.name, field.help, field.kind, func() (float64, bool) { return field.value(memory.read()), true })
	}
	registerFunction(r, "go_gc_duration_seconds_sum", "Total garbage collection pause duration in seconds.", CounterType, func() (float64, bool) { return float64(memory.read().PauseTotalNs) / 1e9, true })
	registerFunction(r, "go_gc_duration_seconds_count", "Total number of completed garbage collections.", CounterType, func() (float64, bool) { return float64(memory.read().NumGC), true })
	for _, field := range []struct{ name, key, help string }{
		{"go_gc_gogc_percent", "/gc/gogc:percent", "Heap size target percentage configured by the user."},
		{"go_gc_gomemlimit_bytes", "/gc/gomemlimit:bytes", "Go runtime memory limit in bytes."},
	} {
		registerFunction(r, field.name, field.help, GaugeType, func() (float64, bool) {
			samples := []rmetrics.Sample{{Name: field.key}}
			rmetrics.Read(samples)
			if samples[0].Value.Kind() != rmetrics.KindUint64 {
				return 0, false
			}
			return float64(samples[0].Value.Uint64()), true
		})
	}
	registerProcessMetrics(r)
}
