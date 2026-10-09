// Copyright (C) 2026
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Set MOSDNS_CN_SITE_BENCH_FILE to exercise a real deployed rule list. Keep
// large, changeable deployment data out of normal unit tests.
func benchmarkCNSite(b *testing.B) (*MixMatcher[struct{}], []string) {
	b.Helper()
	path := os.Getenv("MOSDNS_CN_SITE_BENCH_FILE")
	if path == "" {
		b.Skip("set MOSDNS_CN_SITE_BENCH_FILE to a CN-site rule file")
	}
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	m := NewDomainMixMatcher()
	if err := LoadFromTextReader[struct{}](m, f, nil); err != nil {
		b.Fatal(err)
	}
	f.Close()
	f, err = os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "domain:") {
			s = strings.TrimPrefix(s, "domain:")
		} else if strings.Contains(s, ":") {
			continue
		}
		domains = append(domains, s)
	}
	if err := scanner.Err(); err != nil {
		b.Fatal(err)
	}
	if len(domains) == 0 {
		b.Fatal("no suffix rules found")
	}
	return m, domains
}

func BenchmarkCNSiteMatch(b *testing.B) {
	m, domains := benchmarkCNSite(b)
	for _, mode := range []string{"exact", "subdomain", "miss", "websites"} {
		b.Run(mode, func(b *testing.B) {
			queries := make([]string, 4096)
			websites := []string{"www.qq.com.", "www.taobao.com.", "img.alicdn.com.", "qlogo.cn.", "gtimg.com.", "www.google.com.", "example.com.", "static.cloudflareinsights.com."}
			for i := range queries {
				s := domains[(i*7919)%len(domains)]
				switch mode {
				case "exact":
					queries[i] = s
				case "subdomain":
					queries[i] = "cdn.images." + s + "."
				case "miss":
					queries[i] = fmt.Sprintf("unknown-%d.miss.invalid.", i)
				case "websites":
					queries[i] = websites[i%len(websites)]
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Match(queries[i%len(queries)])
			}
		})
	}
}

func BenchmarkCNSiteLoad(b *testing.B) {
	path := os.Getenv("MOSDNS_CN_SITE_BENCH_FILE")
	if path == "" {
		b.Skip("set MOSDNS_CN_SITE_BENCH_FILE to a CN-site rule file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := NewDomainMixMatcher()
		if err := LoadFromTextReader[struct{}](m, strings.NewReader(string(data)), nil); err != nil {
			b.Fatal(err)
		}
	}
}
