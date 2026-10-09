# Lightweight metrics

The cache, forward and metrics_collector plugins export the same `mosdns_*`
families, HELP, TYPE, constant labels and counter/gauge/histogram samples as
before. Histograms include cumulative finite buckets, the `+Inf` bucket and
`_sum`/`_count`. Counters use atomic integer increments on the query path; gauges
use atomic values; a histogram observation and snapshot each lock only that
histogram. A scrape copies registration entries before calling gauge callbacks.

The `/metrics` endpoint serves Prometheus text format 0.0.4. The implementation
supports ordinary gzip HTTP compression using the standard library. It does not
negotiate protobuf/OpenMetrics or zstd compression. UTF-8 names and
labels use the same quoted-name text representation as the prior formatter.
HTTP name escaping is not negotiated through `Accept`: UTF-8 names remain
quoted and require a compatible scraper. The previous HTTP handler could
rewrite names with underscore escaping. Existing plugin metric/label names
are ASCII and are unaffected by this extension-interface difference.
Colon-containing label names are now quoted correctly; the prior formatter
emitted an invalid unquoted label even though it allowed the name at registration.
The old client and formatter remain as differential test oracles only.

`Mosdns.GetMetricsReg()` now returns this package's `Registerer`, replacing
`prometheus.Registerer`. External Go plugins must import
`github.com/IrineSistiana/mosdns/v5/pkg/metrics` and use its scalar constructors
and `WrapRegistererWithPrefix`. The usage structure is unchanged:

```go
c := metrics.NewCounter(metrics.CounterOpts{
    Name: "query_total", Help: "Queries processed", ConstLabels: metrics.Labels{"tag": tag},
})
err := m.GetMetricsReg().Register(c) // exports mosdns_query_total
c.Inc()
```

Custom collectors implement `Descriptor() Descriptor` and `Snapshot() *Metric`;
one collector represents one series. `Snapshot` must synchronize its own data
and return an independent sample on every call. Prometheus `Collector`, vectors, summaries,
protobuf DTOs, exemplars and unchecked collectors are not source-compatible
extension interfaces here. No existing mosdns plugin uses those interfaces.

Duplicate name/label-value registrations are rejected. Families retain the same
HELP and label-name schema even after unregistering. Inconsistent family types
and histogram/scalar suffix collisions are rejected at registration, earlier
than the prior registry's scrape-time error. Different values of the same
constant labels share one family. Histograms may use different bucket bounds
for distinct series, just as before.
`AlreadyRegisteredError.ExistingCollector` exposes the original collector even
through nested prefixes, allowing callers to recover and continue updating it.

Useful `go_*` memory/allocation, goroutine, thread, GC pause total/count, GOGC,
memory limit and GOMAXPROCS samples remain. Memory and Linux process snapshots
are refreshed at most once per 100 ms. The previous GC summary quantiles and
the broader runtime-metric set are not exported. GC pause `_sum` and `_count`
are standalone counters; their HELP/TYPE metadata differs from the previous
summary while the sample meanings remain cumulative pause time and GC count.
Memory samples use `runtime.ReadMemStats`, which briefly pauses the runtime;
isolated counter/histogram benchmarks do not measure scrape or DNS latency.

Linux/macOS retain CPU time, open/max descriptors and virtual-memory limit.
Linux also exports current virtual/resident memory, exact kernel process start
time (AT_CLKTCK plus stat/btime), and network counters. Network counters cover
the process's **network namespace**, as `/proc/self/net/dev` does; they cannot
attribute traffic to this process alone. On macOS, current resident/virtual
memory and kernel process birth time are omitted rather than approximated.
Other platforms currently export Go metrics without process samples. Unavailable
OS samples are omitted without preventing business metrics from being scraped.

Shared JSON fixtures are unchanged. Tests compare the new text against the old
client for escaping, UTF-8 names, descriptors, bucket/count/sum and special float
observations, and separately check concurrent updates/scrapes and the HTTP path.
