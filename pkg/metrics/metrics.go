// SPDX-License-Identifier: GPL-3.0-or-later
// Package metrics implements the text metrics used by mosdns without a protobuf
// or Prometheus client runtime. Updates are safe during concurrent scrapes.
package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

type Labels map[string]string

type Opts struct {
	Namespace, Subsystem, Name, Help string
	ConstLabels                      Labels
}
type CounterOpts = Opts
type GaugeOpts = Opts
type HistogramOpts struct {
	Namespace, Subsystem, Name, Help string
	ConstLabels                      Labels
	Buckets                          []float64
}

type MetricType string

const (
	CounterType   MetricType = "COUNTER"
	GaugeType     MetricType = "GAUGE"
	HistogramType MetricType = "HISTOGRAM"
)

func (t MetricType) String() string { return string(t) }

// Descriptor is the immutable name, help, type and constant labels of one series.
type Descriptor struct {
	Name, Help string
	Type       MetricType
	Labels     Labels
	err        error
}

type Collector interface {
	Descriptor() Descriptor
	// Snapshot returns an independent sample on every call. Custom collectors
	// must synchronize their own data and must not reuse a mutable returned sample.
	Snapshot() *Metric
}
type Counter interface {
	Collector
	Inc()
	Add(float64)
}
type Gauge interface {
	Collector
	Set(float64)
	Inc()
	Dec()
	Add(float64)
	Sub(float64)
}
type GaugeFunc interface{ Collector }
type Histogram interface {
	Collector
	Observe(float64)
}
type Registerer interface {
	Register(Collector) error
	MustRegister(...Collector)
	Unregister(Collector) bool
}

type LabelPair struct{ Name, Value string }

func (p *LabelPair) GetName() string  { return p.Name }
func (p *LabelPair) GetValue() string { return p.Value }

type Value struct{ Value float64 }

func (v *Value) GetValue() float64 {
	if v == nil {
		return 0
	}
	return v.Value
}

type Bucket struct {
	UpperBound      float64
	CumulativeCount uint64
}

func (b *Bucket) GetUpperBound() float64     { return b.UpperBound }
func (b *Bucket) GetCumulativeCount() uint64 { return b.CumulativeCount }
func (b *Bucket) String() string {
	return fmt.Sprintf("le=%g count=%d", b.UpperBound, b.CumulativeCount)
}

type HistogramData struct {
	SampleCount uint64
	SampleSum   float64
	Bucket      []*Bucket
}

func (h *HistogramData) GetSampleCount() uint64 { return h.SampleCount }
func (h *HistogramData) GetSampleSum() float64  { return h.SampleSum }

type Metric struct {
	Label     []*LabelPair
	Counter   *Value
	Gauge     *Value
	Histogram *HistogramData
}

func (m *Metric) GetCounter() *Value     { return m.Counter }
func (m *Metric) GetGauge() *Value       { return m.Gauge }
func (m *Metric) GetLabel() []*LabelPair { return m.Label }
func (m *Metric) String() string {
	return fmt.Sprintf("labels=%v counter=%v gauge=%v histogram=%v", m.Label, m.Counter, m.Gauge, m.Histogram)
}

type MetricFamily struct {
	Name, Help string
	Type       MetricType
	Metric     []*Metric
}

func (f *MetricFamily) GetName() string      { return f.Name }
func (f *MetricFamily) GetHelp() string      { return f.Help }
func (f *MetricFamily) GetType() MetricType  { return f.Type }
func (f *MetricFamily) GetMetric() []*Metric { return f.Metric }
func (f *MetricFamily) String() string       { return f.Name }

func copyLabels(labels Labels) Labels {
	result := make(Labels, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}
func fullName(namespace, subsystem, name string) string {
	if name == "" {
		return ""
	}
	parts := []string{}
	for _, part := range []string{namespace, subsystem, name} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "_")
}
func descriptor(opts Opts, kind MetricType) Descriptor {
	return Descriptor{Name: fullName(opts.Namespace, opts.Subsystem, opts.Name), Help: opts.Help, Type: kind, Labels: copyLabels(opts.ConstLabels)}
}

type base struct{ desc Descriptor }

func (b *base) Descriptor() Descriptor { d := b.desc; d.Labels = copyLabels(d.Labels); return d }

type counter struct {
	base
	integer  atomic.Uint64
	fraction atomic.Uint64
}

func NewCounter(opts CounterOpts) Counter { return &counter{base: base{descriptor(opts, CounterType)}} }
func (c *counter) Inc()                   { c.integer.Add(1) }
func atomicAdd(v *atomic.Uint64, delta float64) {
	for {
		old := v.Load()
		if v.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+delta)) {
			return
		}
	}
}
func (c *counter) Add(v float64) {
	if v < 0 {
		panic("counter cannot decrease in value")
	}
	integer := uint64(v)
	if float64(integer) == v {
		c.integer.Add(integer)
		return
	}
	atomicAdd(&c.fraction, v)
}
func (c *counter) Snapshot() *Metric {
	return &Metric{Counter: &Value{float64(c.integer.Load()) + math.Float64frombits(c.fraction.Load())}}
}

type gauge struct {
	base
	bits atomic.Uint64
}

func NewGauge(opts GaugeOpts) Gauge { return &gauge{base: base{descriptor(opts, GaugeType)}} }
func (g *gauge) Set(v float64)      { g.bits.Store(math.Float64bits(v)) }
func (g *gauge) Add(v float64)      { atomicAdd(&g.bits, v) }
func (g *gauge) Sub(v float64)      { g.Add(-v) }
func (g *gauge) Inc()               { g.Add(1) }
func (g *gauge) Dec()               { g.Add(-1) }
func (g *gauge) Snapshot() *Metric {
	return &Metric{Gauge: &Value{math.Float64frombits(g.bits.Load())}}
}

type gaugeFunc struct {
	base
	fn func() float64
}

func NewGaugeFunc(opts GaugeOpts, fn func() float64) GaugeFunc {
	if fn == nil {
		panic("nil gauge function")
	}
	return &gaugeFunc{base: base{descriptor(opts, GaugeType)}, fn: fn}
}
func (g *gaugeFunc) Snapshot() *Metric { return &Metric{Gauge: &Value{g.fn()}} }

type histogram struct {
	base
	mu      sync.Mutex
	bounds  []float64
	buckets []uint64 // non-cumulative internally; each observation changes one slot
	count   uint64
	sum     float64
}

func NewHistogram(opts HistogramOpts) Histogram {
	bounds := append([]float64(nil), opts.Buckets...)
	if len(bounds) == 0 {
		bounds = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	}
	if math.IsInf(bounds[len(bounds)-1], 1) {
		bounds = bounds[:len(bounds)-1]
	}
	for i, bound := range bounds {
		if math.IsNaN(bound) || math.IsInf(bound, 1) || (i > 0 && bounds[i-1] >= bound) {
			panic("histogram bounds must increase")
		}
	}
	if _, exists := opts.ConstLabels["le"]; exists {
		panic("histogram cannot use the reserved le label")
	}
	return &histogram{base: base{descriptor(Opts{Namespace: opts.Namespace, Subsystem: opts.Subsystem, Name: opts.Name, Help: opts.Help, ConstLabels: opts.ConstLabels}, HistogramType)}, bounds: bounds, buckets: make([]uint64, len(bounds))}
}
func (h *histogram) Observe(v float64) {
	index := sort.Search(len(h.bounds), func(i int) bool { return v <= h.bounds[i] })
	h.mu.Lock()
	h.count++
	h.sum += v
	if index < len(h.buckets) {
		h.buckets[index]++
	}
	h.mu.Unlock()
}
func (h *histogram) Snapshot() *Metric {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := &HistogramData{SampleCount: h.count, SampleSum: h.sum, Bucket: make([]*Bucket, len(h.bounds))}
	var cumulative uint64
	for i, bound := range h.bounds {
		cumulative += h.buckets[i]
		d.Bucket[i] = &Bucket{bound, cumulative}
	}
	return &Metric{Histogram: d}
}

type registered struct {
	collector Collector
	desc      Descriptor
	key       string
}
type schema struct {
	help  string
	kind  MetricType
	names string
}
type Registry struct {
	mu      sync.RWMutex
	series  map[string]registered
	schemas map[string]schema // retain dimensions even after Unregister, as before
}

func NewRegistry() *Registry {
	return &Registry{series: make(map[string]registered), schemas: make(map[string]schema)}
}
func labelNames(labels Labels) []string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func validName(name string, metric bool) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c == '_' || metric && c == ':' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
func keyFor(d Descriptor) string {
	var b strings.Builder
	for _, value := range append([]string{d.Name}, labelNames(d.Labels)...) {
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	for _, name := range labelNames(d.Labels) {
		value := d.Labels[name]
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	return b.String()
}

func dimensionKey(names []string) string {
	var b strings.Builder
	for _, name := range names {
		b.WriteString(strconv.Itoa(len(name)))
		b.WriteByte(':')
		b.WriteString(name)
	}
	return b.String()
}

func unwrapCollector(c Collector) Collector {
	for {
		wrapped, ok := c.(prefixedCollector)
		if !ok {
			return c
		}
		c = wrapped.Collector
	}
}

type AlreadyRegisteredError struct{ ExistingCollector, NewCollector Collector }

func (AlreadyRegisteredError) Error() string {
	return "duplicate metrics collector registration attempted"
}
func (r *Registry) Register(c Collector) error {
	if c == nil {
		return errors.New("nil metrics collector")
	}
	d := c.Descriptor()
	d.Labels = copyLabels(d.Labels)
	if d.err != nil {
		return d.err
	}
	if d.Name == "" || !utf8.ValidString(d.Name) {
		return fmt.Errorf("invalid metric name %q", d.Name)
	}
	if !utf8.ValidString(d.Help) {
		return errors.New("metric help is not UTF-8")
	}
	names := labelNames(d.Labels)
	for _, name := range names {
		if name == "" || !utf8.ValidString(name) || strings.HasPrefix(name, "__") || !utf8.ValidString(d.Labels[name]) {
			return fmt.Errorf("invalid metric label %q", name)
		}
	}
	if d.Type != CounterType && d.Type != GaugeType && d.Type != HistogramType {
		return errors.New("unsupported metric type")
	}
	if d.Type == HistogramType {
		if _, exists := d.Labels["le"]; exists {
			return errors.New("reserved histogram le label")
		}
	}
	key := keyFor(d)
	want := schema{d.Help, d.Type, dimensionKey(names)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, exists := r.schemas[d.Name]; exists && old != want {
		return fmt.Errorf("inconsistent descriptor for %s", d.Name)
	}
	if old, exists := r.series[key]; exists {
		return AlreadyRegisteredError{unwrapCollector(old.collector), c}
	}
	for name, old := range r.schemas {
		if old.kind == HistogramType && (d.Name == name+"_bucket" || d.Name == name+"_sum" || d.Name == name+"_count") || d.Type == HistogramType && (name == d.Name+"_bucket" || name == d.Name+"_sum" || name == d.Name+"_count") {
			return fmt.Errorf("histogram sample name collision for %s", d.Name)
		}
	}
	r.schemas[d.Name] = want
	r.series[key] = registered{c, d, key}
	return nil
}
func (r *Registry) MustRegister(cs ...Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}
func (r *Registry) Unregister(c Collector) bool {
	if c == nil {
		return false
	}
	key := keyFor(c.Descriptor())
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.series[key]; !exists {
		return false
	}
	delete(r.series, key)
	return true
}

type prefixed struct {
	prefix string
	reg    Registerer
}
type prefixedCollector struct {
	prefix string
	Collector
}

func (c prefixedCollector) Descriptor() Descriptor {
	d := c.Collector.Descriptor()
	if d.Name == "" {
		d.err = errors.New("empty metric name before prefix")
	}
	d.Name = c.prefix + d.Name
	return d
}
func WrapRegistererWithPrefix(prefix string, r Registerer) Registerer { return prefixed{prefix, r} }
func (r prefixed) Register(c Collector) error                         { return r.reg.Register(prefixedCollector{r.prefix, c}) }
func (r prefixed) Unregister(c Collector) bool {
	return r.reg.Unregister(prefixedCollector{r.prefix, c})
}
func (r prefixed) MustRegister(cs ...Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}
func optionalSample(c Collector) bool {
	switch c := c.(type) {
	case *functionMetric:
		return true
	case prefixedCollector:
		return optionalSample(c.Collector)
	}
	return false
}
func (r *Registry) Gather() ([]*MetricFamily, error) {
	r.mu.RLock()
	entries := make([]registered, 0, len(r.series))
	for _, entry := range r.series {
		entries = append(entries, entry)
	}
	r.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i].desc, entries[j].desc
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		for _, name := range labelNames(left.Labels) {
			if left.Labels[name] != right.Labels[name] {
				return left.Labels[name] < right.Labels[name]
			}
		}
		return false
	})
	families := make(map[string]*MetricFamily)
	for _, entry := range entries {
		metric := entry.collector.Snapshot()
		if metric == nil && optionalSample(entry.collector) {
			continue
		}
		if metric == nil || entry.desc.Type == CounterType && metric.Counter == nil || entry.desc.Type == GaugeType && metric.Gauge == nil || entry.desc.Type == HistogramType && metric.Histogram == nil {
			return nil, fmt.Errorf("invalid sample for %s", entry.desc.Name)
		}
		metric.Label = make([]*LabelPair, 0, len(entry.desc.Labels))
		for _, name := range labelNames(entry.desc.Labels) {
			metric.Label = append(metric.Label, &LabelPair{name, entry.desc.Labels[name]})
		}
		family := families[entry.desc.Name]
		if family == nil {
			family = &MetricFamily{Name: entry.desc.Name, Help: entry.desc.Help, Type: entry.desc.Type}
			families[entry.desc.Name] = family
		}
		family.Metric = append(family.Metric, metric)
	}
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]*MetricFamily, 0, len(names))
	for _, name := range names {
		result = append(result, families[name])
	}
	return result, nil
}
func escape(value string, label bool) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	if label {
		value = strings.ReplaceAll(value, "\"", "\\\"")
	}
	return value
}
func number(value float64) string { return strconv.FormatFloat(value, 'g', -1, 64) }
func textName(name string) string {
	if validName(name, true) {
		return name
	}
	return "\"" + escape(name, true) + "\""
}
func textLabelName(name string) string {
	if validName(name, false) {
		return name
	}
	return "\"" + escape(name, true) + "\""
}
func sampleName(name string, pairs []*LabelPair, bound *float64) string {
	var b strings.Builder
	inside := !validName(name, true)
	if !inside {
		b.WriteString(name)
	}
	if len(pairs) == 0 && bound == nil && !inside {
		return b.String()
	}
	b.WriteByte('{')
	comma := false
	if inside {
		b.WriteString(textName(name))
		comma = true
	}
	for _, pair := range pairs {
		if comma {
			b.WriteByte(',')
		}
		comma = true
		b.WriteString(textLabelName(pair.Name))
		b.WriteString("=\"")
		b.WriteString(escape(pair.Value, true))
		b.WriteByte('"')
	}
	if bound != nil {
		if comma {
			b.WriteByte(',')
		}
		b.WriteString("le=\"")
		b.WriteString(number(*bound))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// MetricFamilyToText emits Prometheus text format 0.0.4, with cumulative buckets.
func MetricFamilyToText(w io.Writer, f *MetricFamily) (int, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", textName(f.Name), escape(f.Help, false), textName(f.Name), strings.ToLower(string(f.Type)))
	for _, metric := range f.Metric {
		switch f.Type {
		case CounterType:
			fmt.Fprintf(&b, "%s %s\n", sampleName(f.Name, metric.Label, nil), number(metric.Counter.Value))
		case GaugeType:
			fmt.Fprintf(&b, "%s %s\n", sampleName(f.Name, metric.Label, nil), number(metric.Gauge.Value))
		case HistogramType:
			h := metric.Histogram
			for _, bucket := range h.Bucket {
				fmt.Fprintf(&b, "%s %d\n", sampleName(f.Name+"_bucket", metric.Label, &bucket.UpperBound), bucket.CumulativeCount)
			}
			inf := math.Inf(1)
			fmt.Fprintf(&b, "%s %d\n", sampleName(f.Name+"_bucket", metric.Label, &inf), h.SampleCount)
			fmt.Fprintf(&b, "%s %s\n%s %d\n", sampleName(f.Name+"_sum", metric.Label, nil), number(h.SampleSum), sampleName(f.Name+"_count", metric.Label, nil), h.SampleCount)
		default:
			return 0, errors.New("unsupported metric family type")
		}
	}
	n, err := w.Write(b.Bytes())
	if err == nil && n != b.Len() {
		err = io.ErrShortWrite
	}
	return n, err
}
