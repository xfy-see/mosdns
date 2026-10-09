/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package domain

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"io"
	"strings"
	"unicode"
)

// ParseStringFunc parse data string to matcher pattern and additional attributions.
type ParseStringFunc[T any] func(s string) (pattern string, v T, err error)

// check if s only contains a domain pattern (no other section, no space).
func patternOnly[T any](s string) (pattern string, v T, err error) {
	if strings.IndexFunc(s, unicode.IsSpace) != -1 {
		return "", v, errors.New("rule string has more than one section")
	}
	return s, v, nil
}

// Load loads data from a string, parsing it with parseString function.
func Load[T any](m WriteableMatcher[T], s string, parseString ParseStringFunc[T]) error {
	if parseString == nil {
		parseString = patternOnly[T]
	}
	pattern, v, err := parseString(s)
	if err != nil {
		return err
	}
	return m.Add(pattern, v)
}

// LoadFromTextReader loads multiple lines from reader r. r
func LoadFromTextReader[T any](m WriteableMatcher[T], r io.Reader, parseString ParseStringFunc[T]) error {
	if parseString == nil {
		return loadPatternsFromTextReader(m, r)
	}
	// Custom parsers keep their existing streaming callback behavior.
	lineCounter := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lineCounter++
		s := scanner.Text()
		s = utils.RemoveComment(s, "#")
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}

		err := Load(m, s, parseString)
		if err != nil {
			return fmt.Errorf("line %d: %v", lineCounter, err)
		}
	}
	return scanner.Err()
}

// Freeze a small batch into one immutable string. Matchers retain slices of
// this string rather than a separate allocation for every rule in a large set.
// Scanner's original line length limit, line numbers, and partial-load errors
// are retained. Empty lines and comments are not stored in the batch.
func loadPatternsFromTextReader[T any](m WriteableMatcher[T], r io.Reader) error {
	const batchSize = 32 << 10
	type line struct{ number, start, end int }
	data := make([]byte, 0, batchSize)
	lines := make([]line, 0, 1024)
	flush := func() error {
		text := string(data)
		for _, l := range lines {
			if err := Load(m, text[l.start:l.end], nil); err != nil {
				return fmt.Errorf("line %d: %v", l.number, err)
			}
		}
		data = data[:0]
		lines = lines[:0]
		return nil
	}
	scanner := bufio.NewScanner(r)
	lineCounter := 0
	for scanner.Scan() {
		lineCounter++
		s := scanner.Bytes()
		if i := bytes.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = bytes.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		if len(data)+len(s) > batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
		start := len(data)
		data = append(data, s...)
		lines = append(lines, line{lineCounter, start, len(data)})
	}
	if err := flush(); err != nil {
		return err
	}
	return scanner.Err()
}

func NewDomainMixMatcher() *MixMatcher[struct{}] {
	mixMatcher := NewMixMatcher[struct{}]()
	mixMatcher.SetDefaultMatcher(MatcherDomain)
	return mixMatcher
}
