// SPDX-License-Identifier: GPL-3.0-or-later
// The test-only proxy keeps origin DNS/TCP on OpenWrt. CONNECT preserves TLS.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

var listen = flag.String("listen", "127.0.0.1:18081", "loopback HTTP proxy listener")
var server = flag.String("dns", "127.0.0.1:15361", "owned numeric DNS listener")
var siteFile = flag.String("cn-site", "", "CN-site list")
var ipFile = flag.String("cn-ip", "", "CN-IP list")
var directDevice = flag.String("direct-interface", "br-lan", "existing direct interface")
var tunnelDevice = flag.String("tunnel-interface", "", "existing WireGuard interface")
var directMark = flag.Int("direct-mark", 0, "existing direct routing mark")
var tunnelMark = flag.Int("tunnel-mark", 0, "existing tunnel routing mark")
var sites = domain.NewDomainMixMatcher()
var ips = netlist.NewList()
var outputMu sync.Mutex
var slots = make(chan struct{}, 64)

func emit(v any) { outputMu.Lock(); defer outputMu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(v) }

func origin(authority string) (string, string, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || (port != "80" && port != "443") || host == "" {
		return "", "", fmt.Errorf("only origin ports 80 and 443 are supported")
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), port, nil
}

func public(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() { return false }
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(block).Contains(ip) { return false }
	}
	return true
}

func errorText(err error) string { if err == nil { return "" }; return err.Error() }

func resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	q.SetEdns0(1232, false)
	start := time.Now()
	r, _, err := (&dns.Client{Net: "udp", Timeout: 4 * time.Second}).ExchangeContext(ctx, q, *server)
	if err == nil && r != nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp", Timeout: 4 * time.Second}).ExchangeContext(ctx, q, *server)
	}
	if err == nil && (r == nil || r.Id != q.Id || !r.Response || r.Truncated || len(r.Question) != 1 || r.Question[0] != q.Question[0] || r.Rcode != dns.RcodeSuccess) {
		err = fmt.Errorf("invalid or unsuccessful DNS response")
	}
	var answer []netip.Addr
	if err == nil {
		for _, rr := range r.Answer {
			if a, ok := rr.(*dns.A); ok { if ip, e := netip.ParseAddr(a.A.String()); e == nil { answer = append(answer, ip) } }
		}
		if len(answer) == 0 { err = fmt.Errorf("no IPv4 answer") }
	}
	emit(map[string]any{"kind": "dns", "host": host, "elapsed_ms": float64(time.Since(start).Microseconds()) / 1000, "answers": answer, "ok": err == nil, "error": errorText(err)})
	return answer, err
}

func dial(ctx context.Context, authority string) (net.Conn, error) {
	host, port, err := origin(authority)
	if err != nil { return nil, err }
	addresses, err := resolve(ctx, host)
	if err != nil { return nil, err }
	_, cnSite := sites.Match(host)
	last := fmt.Errorf("no public IPv4 destination")
	for _, ip := range addresses {
		if !public(ip) { continue }
		device, mark, route := *tunnelDevice, *tunnelMark, "tunnel"
		if cnSite || ips.Contains(ip) { device, mark, route = *directDevice, *directMark, "direct" }
		d := net.Dialer{Timeout: 4 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			err := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
				if sockErr == nil { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) }
			})
			if err != nil { return err }; return sockErr
		}}
		start := time.Now()
		c, e := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		emit(map[string]any{"kind": "origin_dial", "host": host, "cn_site": cnSite, "ip": ip.String(), "route": route, "interface": device, "mark": mark, "elapsed_ms": float64(time.Since(start).Microseconds()) / 1000, "ok": e == nil, "error": errorText(e)})
		if e == nil { _ = c.SetDeadline(time.Now().Add(65 * time.Second)); return c, nil }
		last = e
	}
	return nil, last
}

func proxy(w http.ResponseWriter, r *http.Request) {
	select { case slots <- struct{}{}: defer func() { <-slots }(); default: http.Error(w, "connection limit", 503); return }
	if r.Method != http.MethodConnect { http.Error(w, "this page test uses HTTPS CONNECT", 405); return }
	upstream, err := dial(r.Context(), r.Host)
	if err != nil { http.Error(w, "origin connection failed", 502); return }
	defer upstream.Close()
	client, buf, err := w.(http.Hijacker).Hijack()
	if err != nil { return }; defer client.Close()
	_ = client.SetDeadline(time.Now().Add(65 * time.Second))
	_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err = buf.Flush(); err != nil { return }
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, buf); if c, ok := upstream.(*net.TCPConn); ok { _ = c.CloseWrite() }; close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close(); _ = upstream.Close(); <-done
}

func main() {
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() { panic("listener must be a numeric loopback address") }
	dnsHost, _, err := net.SplitHostPort(*server)
	if err != nil || net.ParseIP(dnsHost) == nil || !net.ParseIP(dnsHost).IsLoopback() { panic("DNS must be the owned numeric loopback listener") }
	if *tunnelDevice == "" || *directDevice == "" { panic("both existing egress interfaces are required") }
	for _, input := range []struct{ path string; load func(io.Reader) error }{
		{*siteFile, func(r io.Reader) error { return domain.LoadFromTextReader(sites, r, nil) }},
		{*ipFile, func(r io.Reader) error { return netlist.LoadFromReader(ips, r) }},
	} {
		f, e := os.Open(input.path); if e != nil { panic(e) }
		e = input.load(f); _ = f.Close(); if e != nil { panic(e) }
	}
	ips.Sort()
	emit(map[string]any{"kind": "ready", "listen": *listen, "dns": *server})
	s := &http.Server{Addr: *listen, Handler: http.HandlerFunc(proxy), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	if err := s.ListenAndServe(); err != nil { panic(err) }
}
