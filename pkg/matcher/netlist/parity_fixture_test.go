// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

package netlist

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type netlistFixtureQuery struct {
	IP      string `json:"ip"`
	Matches bool   `json:"matches"`
}

type netlistFixtureCase struct {
	Name         string                `json:"name"`
	Rules        []string              `json:"rules"`
	InvalidRules []string              `json:"invalid_rules"`
	ExpectedLen  int                   `json:"expected_len"`
	Queries      []netlistFixtureQuery `json:"queries"`
	Text         string                `json:"text"`
	ErrorLine    int                   `json:"error_line"`
}

func TestSharedNetListFixture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate fixture relative to this test")
	}
	fixturePath := filepath.Join(filepath.Dir(source), "../../../tests/fixtures/matcher_netlist.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version   int                  `json:"format_version"`
		Cases     []netlistFixtureCase `json:"cases"`
		LoadCases []netlistFixtureCase `json:"load_cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatalf("unsupported fixture format %d", fixture.Version)
	}
	check := func(t *testing.T, l *List, c netlistFixtureCase) {
		t.Helper()
		l.Sort()
		if got := l.Len(); got != c.ExpectedLen {
			t.Fatalf("Len() = %d, want %d", got, c.ExpectedLen)
		}
		for _, q := range c.Queries {
			addr, err := netip.ParseAddr(q.IP)
			if err != nil {
				t.Fatalf("invalid query fixture %q: %v", q.IP, err)
			}
			if got := l.Contains(addr); got != q.Matches {
				t.Errorf("Contains(%q) = %v, want %v", q.IP, got, q.Matches)
			}
		}
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			l := NewList()
			for _, rule := range c.Rules {
				if err := LoadFromText(l, rule); err != nil {
					t.Fatalf("LoadFromText(%q): %v", rule, err)
				}
			}
			for _, rule := range c.InvalidRules {
				if err := LoadFromText(l, rule); err == nil {
					t.Errorf("LoadFromText(%q) accepted invalid rule", rule)
				}
			}
			check(t, l, c)
		})
	}
	for _, c := range fixture.LoadCases {
		t.Run(c.Name, func(t *testing.T) {
			l := NewList()
			err := LoadFromReader(l, strings.NewReader(c.Text))
			if c.ErrorLine == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("line #%d:", c.ErrorLine)) {
				t.Fatalf("want error at line %d, got %v", c.ErrorLine, err)
			}
			check(t, l, c)
		})
	}
}
