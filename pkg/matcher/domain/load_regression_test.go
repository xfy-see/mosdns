// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
)

type retainedPatternMatcher struct{ patterns []string }

func (m *retainedPatternMatcher) Add(s string, _ struct{}) error {
	m.patterns = append(m.patterns, s)
	return nil
}
func (m *retainedPatternMatcher) Match(s string) (struct{}, bool) { return struct{}{}, false }

func loadReference(m WriteableMatcher[struct{}], r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for number := 1; scanner.Scan(); number++ {
		s := strings.TrimSpace(utils.RemoveComment(scanner.Text(), "#"))
		if s == "" {
			continue
		}
		if err := Load(m, s, nil); err != nil {
			return fmt.Errorf("line %d: %v", number, err)
		}
	}
	return scanner.Err()
}

func TestRuleLoaderPreservesBatchStringsAndErrors(t *testing.T) {
	var data strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&data, "\u00a0 domain:host-%d.example.test. \t# comment\r\n\n", i)
	}
	valid := data.String()
	for name, text := range map[string]string{
		"multiple_batches":            valid,
		"invalid_at_end":              valid + "full:bad rule\n",
		"scanner_limit":               valid + strings.Repeat("a", 70<<10),
		"parser_before_scanner_error": "good.test\ninvalid rule\n" + strings.Repeat("a", 70<<10),
		"large_single_rule":           "good.test\nfull:" + strings.Repeat("a", 40<<10) + ".test\nnext.test\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, want := new(retainedPatternMatcher), new(retainedPatternMatcher)
			gotErr := LoadFromTextReader[struct{}](got, strings.NewReader(text), nil)
			wantErr := loadReference(want, strings.NewReader(text))
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got.patterns, want.patterns) {
				t.Fatalf("loader differs: errors=%v/%v, retained rules=%d/%d", gotErr, wantErr, len(got.patterns), len(want.patterns))
			}
		})
	}
}

type failingRuleReader struct{}

func (failingRuleReader) Read([]byte) (int, error) { return 0, errors.New("reader failure") }

func TestRuleLoaderKeepsRulesBeforeReaderError(t *testing.T) {
	m := NewDomainMixMatcher()
	err := LoadFromTextReader[struct{}](m, io.MultiReader(strings.NewReader("example.com\n"), failingRuleReader{}), nil)
	if err == nil || err.Error() != "reader failure" {
		t.Fatalf("reader error=%v", err)
	}
	if _, ok := m.Match("www.example.com."); !ok {
		t.Fatal("rule preceding the reader error was lost")
	}
}
