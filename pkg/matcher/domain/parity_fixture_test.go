// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type domainFixtureQuery struct {
	Domain  string `json:"domain"`
	Matches bool   `json:"matches"`
}

type domainFixtureCase struct {
	Name         string               `json:"name"`
	Rules        []string             `json:"rules"`
	InvalidRules []string             `json:"invalid_rules"`
	ExpectedLen  int                  `json:"expected_len"`
	Queries      []domainFixtureQuery `json:"queries"`
	Text         string               `json:"text"`
	ErrorLine    int                  `json:"error_line"`
}

// The Rust port reads this same file. Keep the existing Go tests as the oracle
// and add edge cases to the shared fixture before changing either implementation.
func TestSharedDomainMatcherFixture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate fixture relative to this test")
	}
	fixturePath := filepath.Join(filepath.Dir(source), "../../../tests/fixtures/matcher_domain.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version   int                 `json:"format_version"`
		Cases     []domainFixtureCase `json:"cases"`
		LoadCases []domainFixtureCase `json:"load_cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatalf("unsupported fixture format %d", fixture.Version)
	}
	check := func(t *testing.T, m *MixMatcher[struct{}], c domainFixtureCase) {
		t.Helper()
		if got := m.Len(); got != c.ExpectedLen {
			t.Fatalf("Len() = %d, want %d", got, c.ExpectedLen)
		}
		for _, q := range c.Queries {
			if _, got := m.Match(q.Domain); got != q.Matches {
				t.Errorf("Match(%q) = %v, want %v", q.Domain, got, q.Matches)
			}
		}
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			m := NewDomainMixMatcher()
			for _, rule := range c.Rules {
				if err := m.Add(rule, struct{}{}); err != nil {
					t.Fatalf("Add(%q): %v", rule, err)
				}
			}
			for _, rule := range c.InvalidRules {
				if err := m.Add(rule, struct{}{}); err == nil {
					t.Errorf("Add(%q) accepted invalid rule", rule)
				}
			}
			check(t, m, c)
		})
	}
	for _, c := range fixture.LoadCases {
		t.Run(c.Name, func(t *testing.T) {
			m := NewDomainMixMatcher()
			err := LoadFromTextReader[struct{}](m, strings.NewReader(c.Text), nil)
			if c.ErrorLine == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("line %d:", c.ErrorLine)) {
				t.Fatalf("want error at line %d, got %v", c.ErrorLine, err)
			}
			check(t, m, c)
		})
	}
}
