// Copyright (C) 2026
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// This reference is the original reverse-label trie. Its edge behavior is part
// of the existing API, including root Len and malformed empty DNS labels.
type referenceDomainNode struct {
	children map[string]*referenceDomainNode
	value    int
	hasValue bool
}

func (n *referenceDomainNode) add(s string, value int) {
	scanner := NewReverseDomainScanner(NormalizeDomain(s))
	for scanner.Scan() {
		label := scanner.NextLabel()
		if n.children == nil {
			n.children = make(map[string]*referenceDomainNode)
		}
		if n.children[label] == nil {
			n.children[label] = new(referenceDomainNode)
		}
		n = n.children[label]
	}
	n.value, n.hasValue = value, true
}
func (n *referenceDomainNode) match(s string) (int, bool) {
	scanner := NewReverseDomainScanner(NormalizeDomain(s))
	value, ok := n.value, n.hasValue
	for scanner.Scan() {
		next := n.children[scanner.NextLabel()]
		if next == nil {
			break
		}
		n = next
		if n.hasValue {
			value, ok = n.value, true
		}
	}
	return value, ok
}

func (n *referenceDomainNode) Add(s string, v int) error  { n.add(s, v); return nil }
func (n *referenceDomainNode) Match(s string) (int, bool) { return n.match(s) }

type referenceMixMatcher struct {
	full    *FullMatcher[int]
	domain  *referenceDomainNode
	regex   *RegexMatcher[int]
	keyword *KeywordMatcher[int]
}

func (m *referenceMixMatcher) Add(s string, value int) error {
	typ, pattern, ok := strings.Cut(s, ":")
	if !ok {
		typ, pattern = MatcherDomain, s
	}
	if typ == "" {
		typ = MatcherDomain
	}
	switch typ {
	case MatcherFull:
		return m.full.Add(pattern, value)
	case MatcherDomain:
		return m.domain.Add(pattern, value)
	case MatcherRegexp:
		return m.regex.Add(pattern, value)
	case MatcherKeyword:
		return m.keyword.Add(pattern, value)
	}
	return fmt.Errorf("unsupported matcher %s", typ)
}

func (m *referenceMixMatcher) Match(s string) (int, bool) {
	for _, matcher := range [...]Matcher[int]{m.full, m.domain, m.regex, m.keyword} {
		if v, ok := matcher.Match(s); ok {
			return v, true
		}
	}
	return 0, false
}

func TestCNSiteMatchesOriginalTrie(t *testing.T) {
	path := os.Getenv("MOSDNS_CN_SITE_BENCH_FILE")
	if path == "" {
		t.Skip("set MOSDNS_CN_SITE_BENCH_FILE to a CN-site rule file")
	}
	got := NewMixMatcher[int]()
	got.SetDefaultMatcher(MatcherDomain)
	want := &referenceMixMatcher{NewFullMatcher[int](), new(referenceDomainNode), NewRegexMatcher[int](), NewKeywordMatcher[int]()}
	for _, m := range []WriteableMatcher[int]{got, want} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		err = LoadFromTextReader[int](m, f, nil)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	check := func(s string) {
		t.Helper()
		_, gotOK := got.Match(s)
		_, wantOK := want.Match(s)
		if gotOK != wantOK {
			t.Fatalf("Match(%q)=%v, original trie=%v", s, gotOK, wantOK)
		}
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := scanner.Text()
		if typ, pattern, ok := strings.Cut(s, ":"); ok {
			if typ != MatcherDomain && typ != MatcherFull {
				continue
			}
			s = pattern
		}
		check(s)
		check("cdn.images." + s + ".")
		check(strings.ToUpper(s) + ".")
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4096; i++ {
		check(fmt.Sprintf("unknown-%d.miss.invalid.", i))
	}
}

func TestSubDomainMatcherReference(t *testing.T) {
	r := rand.New(rand.NewSource(20261008))
	rules := []string{"", ".", "..", "...", "example.com", "a.example.com", ".leading", "..leading", "a..b", "İ.example", "ΟΣ.example", "ǅ.example"}
	for i := 0; i < 4096; i++ {
		rules = append(rules, fmt.Sprintf("host%d.group%d.test", i, r.Intn(47)))
	}
	queries := []string{"", ".", "..", "...", "....", ".example.com", "..example.com", "example.com..", "example.com...", "a..b", ".a..b", "i.example", "οσ.example", "ǆ.example", "unmatched.invalid", "badexample.com"}
	for _, s := range rules {
		queries = append(queries, s, "cdn."+s, strings.ToUpper(s)+".")
	}
	for i := 0; i < 20000; i++ {
		n := r.Intn(8)
		var s strings.Builder
		for j := 0; j < n; j++ {
			s.WriteByte("aAb.."[r.Intn(5)])
		}
		queries = append(queries, s.String())
	}
	// Rebuild without and with the fallback root to verify returned zero values
	// and the longest suffix, independently of insertion order and replacements.
	for _, withRoot := range []bool{false, true} {
		m := NewSubDomainMatcher[int]()
		reference := new(referenceDomainNode)
		for i, s := range rules {
			if !withRoot && (s == "" || s == "." || s == "..") {
				continue
			}
			if err := m.Add(s, i); err != nil {
				t.Fatal(err)
			}
			reference.add(s, i)
		}
		for i := len(rules) - 1; i >= 0; i -= 13 {
			s := rules[i]
			if !withRoot && (s == "" || s == "." || s == "..") {
				continue
			}
			m.Add(s, -i)
			reference.add(s, -i)
		}
		for _, s := range queries {
			got, gotOK := m.Match(s)
			want, wantOK := reference.match(s)
			if got != want || gotOK != wantOK {
				t.Fatalf("root=%v Match(%q)=(%d,%v), reference=(%d,%v)", withRoot, s, got, gotOK, want, wantOK)
			}
		}
	}
}
