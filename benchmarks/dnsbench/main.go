// SPDX-License-Identifier: GPL-3.0-or-later
// dnsbench provides identical bounded workloads for both implementations.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var mode = flag.String("mode", "load", "load, probe, or mock")
var addr = flag.String("addr", "127.0.0.1:15331", "server address")
var network = flag.String("net", "udp", "udp or tcp")
var count = flag.Int("n", 10000, "bounded query count")
var workers = flag.Int("c", 16, "concurrent clients")
var names = flag.String("names", "www.baidu.com,www.qq.com,www.google.com", "comma-separated query names")
var namesFile = flag.String("file", "", "query file: name [type] per line")
var unique = flag.Bool("unique", false, "prefix each name with query index (mock cold-cache only)")
var prefix = flag.String("prefix", "q", "unique workload prefix; use a fresh value for every trial")
var expectMock = flag.Bool("expect-mock", false, "validate every answer against the deterministic split workload")
var timeout = flag.Duration("timeout", 2*time.Second, "per query deadline")
var branch = flag.String("branch", "cn", "mock answer source: cn or foreign")

type query struct {
	name string
	typ  uint16
}
type sample struct {
	ms    float64
	rcode int
	err   string
}

func validMock(q, r *dns.Msg) bool {
	name := strings.ToLower(q.Question[0].Name)
	if strings.HasSuffix(name, "nxdomain.test.") {
		return r.Rcode == dns.RcodeNameError
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		return false
	}
	cn := strings.HasSuffix(name, "cn-site.test.") || strings.HasSuffix(name, "candidate-cn.test.")
	switch rr := r.Answer[0].(type) {
	case *dns.A:
		want := "8.8.8.8"
		if cn {
			want = "223.5.5.5"
		}
		return rr.A.Equal(net.ParseIP(want))
	case *dns.AAAA:
		want := "2001:4860:4860::8888"
		if cn {
			want = "2400:3200::1"
		}
		return rr.AAAA.Equal(net.ParseIP(want))
	}
	return false
}

func queryList() []query {
	var lines []string
	if *namesFile != "" {
		f, e := os.Open(*namesFile)
		if e != nil {
			panic(e)
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			lines = append(lines, s.Text())
		}
		if e = s.Err(); e != nil {
			panic(e)
		}
	} else {
		lines = strings.Split(*names, ",")
	}
	var qs []query
	for _, line := range lines {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		p := strings.Fields(line)
		typ := uint16(dns.TypeA)
		if len(p) > 1 {
			var ok bool
			typ, ok = dns.StringToType[strings.ToUpper(p[1])]
			if !ok {
				panic("unknown query type " + p[1])
			}
		}
		qs = append(qs, query{dns.Fqdn(p[0]), typ})
	}
	if len(qs) == 0 {
		panic("empty query list")
	}
	return qs
}

func mock() {
	var total atomic.Uint64
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		total.Add(1)
		if len(q.Question) != 1 {
			return
		}
		name := strings.ToLower(q.Question[0].Name)
		if strings.HasSuffix(name, "timeout.test.") {
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.RecursionAvailable = true
		if strings.HasSuffix(name, "nxdomain.test.") {
			r.Rcode = dns.RcodeNameError
			r.Ns = append(r.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.test.", Mbox: "hostmaster.test.", Serial: 1, Minttl: 60})
			_ = w.WriteMsg(r)
			return
		}
		cn := strings.HasSuffix(name, "cn-site.test.") || strings.HasSuffix(name, "candidate-cn.test.") || strings.HasSuffix(name, ".cn.")
		ipv4, ipv6 := "8.8.8.8", "2001:4860:4860::8888"
		if *branch == "cn" {
			ipv4, ipv6 = "198.18.0.1", "2001:db8::1"
			if cn {
				ipv4, ipv6 = "223.5.5.5", "2400:3200::1"
			}
		}
		rrh := dns.RR_Header{Name: q.Question[0].Name, Class: q.Question[0].Qclass, Ttl: 300, Rrtype: q.Question[0].Qtype}
		switch q.Question[0].Qtype {
		case dns.TypeA:
			r.Answer = append(r.Answer, &dns.A{Hdr: rrh, A: net.ParseIP(ipv4)})
		case dns.TypeAAAA:
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: rrh, AAAA: net.ParseIP(ipv6)})
		case dns.TypeTXT:
			r.Answer = append(r.Answer, &dns.TXT{Hdr: rrh, Txt: []string{*branch}})
		}
		_ = w.WriteMsg(r)
	})
	go func() {
		for range time.Tick(10 * time.Second) {
			fmt.Fprintf(os.Stderr, "queries=%d\n", total.Load())
		}
	}()
	udp := &dns.Server{Addr: *addr, Net: "udp", Handler: h}
	tcp := &dns.Server{Addr: *addr, Net: "tcp", Handler: h}
	go func() {
		if e := tcp.ListenAndServe(); e != nil {
			panic(e)
		}
	}()
	fmt.Fprintf(os.Stderr, "mock branch=%s listen=%s\n", *branch, *addr)
	if e := udp.ListenAndServe(); e != nil {
		panic(e)
	}
}

func probe(qs []query) {
	c := &dns.Client{Net: *network, Timeout: *timeout}
	for _, x := range qs {
		q := new(dns.Msg)
		q.SetQuestion(x.name, x.typ)
		q.SetEdns0(1232, true)
		r, elapsed, e := c.Exchange(q, *addr)
		out := map[string]any{"name": x.name, "type": dns.TypeToString[x.typ], "elapsed_ms": float64(elapsed.Microseconds()) / 1000}
		if e != nil {
			out["error"] = e.Error()
		} else {
			out["rcode"] = r.Rcode
			out["truncated"] = r.Truncated
			out["id_ok"] = r.Id == q.Id
			var ans []string
			for _, rr := range r.Answer {
				ans = append(ans, rr.String())
			}
			out["answers"] = ans
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	}
}

func load(qs []query) {
	if *count <= 0 || *workers <= 0 || *workers > 1024 {
		panic("invalid n/c")
	}
	samples := make([]sample, *count)
	var index atomic.Int64
	var activeWorkers atomic.Int64
	var setupQueries atomic.Int64
	var wg sync.WaitGroup
	// Establish every worker before timing. A dial racing with shared work can
	// arrive after faster workers finish the entire workload, inflating seconds
	// and never exercising the requested concurrency.
	connections := make([]net.Conn, *workers)
	setupStart := time.Now()
	prepared := make(chan struct{})
	ready := make(chan struct{})
	setupErrors := make(chan error, *workers)
	var initialized, queryReady sync.WaitGroup
	initialized.Add(*workers)
	queryReady.Add(*workers)
	var aborted atomic.Bool
	for w := range connections {
		nc, err := net.DialTimeout(*network, *addr, *timeout)
		if err != nil {
			for _, opened := range connections {
				if opened != nil {
					_ = opened.Close()
				}
			}
			fmt.Fprintf(os.Stderr, "worker %d connection setup failed: %v\n", w, err)
			os.Exit(1)
		}
		if udp, ok := nc.(*net.UDPConn); ok {
			_ = udp.SetReadBuffer(1024 * 1024)
			_ = udp.SetWriteBuffer(1024 * 1024)
		}
		connections[w] = nc
		wg.Add(1)
		go func(w int, nc net.Conn) {
			defer wg.Done()
			defer nc.Close()
			conn := &dns.Conn{Conn: nc, UDPSize: 65535}
			client := &dns.Client{Net: *network, Timeout: *timeout, UDPSize: 65535}
			// Go imposes a two-second first-read deadline. Initialize TCP
			// immediately, then keep prepared connections alive while the
			// remaining clients dial. All exchanges have one owner per socket.
			prepareQuery := func() error {
				x := qs[0]
				name := x.name
				if *unique {
					name = fmt.Sprintf("setup-%s%d.%s", *prefix, w, name)
				}
				q := new(dns.Msg)
				q.SetQuestion(name, x.typ)
				q.SetEdns0(1232, false)
				setupQueries.Add(1)
				r, _, err := client.ExchangeWithConn(q, conn)
				if err == nil && (!r.Response || r.Id != q.Id || len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, q.Question[0].Name) || r.Question[0].Qtype != x.typ || (*expectMock && !validMock(q, r))) {
					err = fmt.Errorf("connection preparation response validation failed")
				}
				return err
			}
			var setupErr error
			if *network == "tcp" {
				setupErr = prepareQuery()
			}
			initialized.Done()
			if setupErr == nil && *network == "tcp" {
				ticker := time.NewTicker(2 * time.Second)
			prepareLoop:
				for {
					select {
					case <-prepared:
						break prepareLoop
					case <-ticker.C:
						if setupErr = prepareQuery(); setupErr != nil {
							break prepareLoop
						}
					}
				}
				ticker.Stop()
			} else if setupErr == nil {
				<-prepared
			}
			if setupErr != nil {
				setupErrors <- fmt.Errorf("worker %d: %w", w, setupErr)
			}
			queryReady.Done()
			<-ready
			if aborted.Load() {
				return
			}
			active := false
			for {
				i := int(index.Add(1) - 1)
				if i >= *count {
					return
				}
				if !active {
					activeWorkers.Add(1)
					active = true
				}
				x := qs[i%len(qs)]
				q := new(dns.Msg)
				name := x.name
				if *unique {
					name = fmt.Sprintf("%s%d.%s", *prefix, i, name)
				}
				q.SetQuestion(name, x.typ)
				q.Id = uint16(i + 1)
				q.SetEdns0(1232, false)
				t := time.Now()
				r, _, e := client.ExchangeWithConn(q, conn)
				samples[i].ms = float64(time.Since(t).Nanoseconds()) / 1e6
				if e != nil {
					samples[i].err = e.Error()
				} else if !r.Response || r.Id != q.Id || len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, q.Question[0].Name) || r.Question[0].Qtype != x.typ {
					samples[i].err = "response validation failed"
				} else if *expectMock && !validMock(q, r) {
					samples[i].err = "split answer validation failed"
				} else {
					samples[i].rcode = r.Rcode
				}
			}
		}(w, nc)
	}
	initialized.Wait()
	close(prepared)
	queryReady.Wait()
	setupSeconds := time.Since(setupStart).Seconds()
	if len(setupErrors) > 0 {
		aborted.Store(true)
		close(ready)
		wg.Wait()
		close(setupErrors)
		for err := range setupErrors {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
	start := time.Now()
	close(ready)
	wg.Wait()
	seconds := time.Since(start).Seconds()
	lat := make([]float64, 0, *count)
	rcodes := map[int]int{}
	errs := map[string]int{}
	errorCount := 0
	for _, s := range samples {
		if s.err != "" {
			errorCount++
			errs[s.err]++
		} else {
			lat = append(lat, s.ms)
			rcodes[s.rcode]++
		}
	}
	sort.Float64s(lat)
	percent := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(float64(len(lat)-1) * p)
		return lat[i]
	}
	var sum float64
	for _, v := range lat {
		sum += v
	}
	mean := float64(0)
	if len(lat) > 0 {
		mean = sum / float64(len(lat))
	}
	out := map[string]any{"server": *addr, "network": *network, "queries": *count, "concurrency": *workers, "active_workers": activeWorkers.Load(), "unique": *unique, "seconds": seconds, "connection_setup_seconds": setupSeconds, "setup_queries": setupQueries.Load(), "qps": float64(*count-errorCount) / seconds, "errors": errorCount, "error_types": errs, "rcodes": rcodes, "mean_ms": mean, "p50_ms": percent(.5), "p95_ms": percent(.95), "p99_ms": percent(.99), "max_ms": percent(1)}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	flag.Parse()
	switch *mode {
	case "mock":
		mock()
	case "probe":
		probe(queryList())
	case "load":
		load(queryList())
	default:
		panic("unknown mode")
	}
}
