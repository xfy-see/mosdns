// SPDX-License-Identifier: GPL-3.0-or-later
package utils

import (
	"reflect"
	"testing"
)

// Expected values and error outcomes were captured from mapstructure v1.5.0
// before removing that dependency. Keep all legacy cases without linking a
// second decoder solely to generate an oracle during the test.
func TestWeakDecodeLegacyContract(t *testing.T) {
	type child struct {
		Timeout uint     `yaml:"timeout"`
		Names   []string `yaml:"names"`
	}
	type config struct {
		Name     string            `yaml:"tag"`
		Enabled  bool              `yaml:"enabled"`
		Size     int               `yaml:"size"`
		Ratio    float64           `yaml:"ratio"`
		Child    child             `yaml:"child"`
		Args     map[string]string `yaml:"args"`
		Optional *child            `yaml:"optional"`
	}
	cases := []struct {
		name   string
		input  any
		want   config
		failed bool
	}{
		{"nil", nil, config{}, false},
		{"empty", map[string]any{}, config{}, false},
		{"yaml-tags", map[string]any{"tag": "dns", "enabled": "true", "size": "8192", "ratio": "1.5"}, config{Name: "dns", Enabled: true, Size: 8192, Ratio: 1.5}, false},
		{"yaml-interface-map", map[any]any{"tag": "dns", "child": map[any]any{"timeout": "5", "names": "dns.example"}}, config{Name: "dns", Child: child{Timeout: 5, Names: []string{"dns.example"}}}, false},
		{"nested-slices", map[string]any{"child": map[string]any{"timeout": 6, "names": []any{"a", 42}}, "args": map[string]any{"port": 53}}, config{Child: child{Timeout: 6, Names: []string{"a", "42"}}, Args: map[string]string{"port": "53"}}, false},
		{"pointer", map[string]any{"optional": map[string]any{"timeout": "6"}}, config{Optional: &child{Timeout: 6}}, false},
		{"case-insensitive", map[string]any{"TAG": "dns", "SIZE": 12}, config{Name: "dns", Size: 12}, false},
		{"unknown", map[string]any{"unexpected": true}, config{}, true},
		{"nested-unknown", map[string]any{"child": map[string]any{"unknown": 1}}, config{}, true},
		{"invalid-number", map[string]any{"size": "not-a-number"}, config{}, true},
		{"invalid-bool", map[string]any{"enabled": "not-a-bool"}, config{}, true},
		{"negative-unsigned", map[string]any{"child": map[string]any{"timeout": -1}}, config{Child: child{Timeout: ^uint(0)}}, false},
		{"null-fields", map[string]any{"tag": nil, "optional": nil}, config{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var after config
			err := WeakDecode(tc.input, &after)
			if (err != nil) != tc.failed || !reflect.DeepEqual(tc.want, after) {
				t.Fatalf("weak decoding changed: want=%+v failed=%v, current=%+v (%v)", tc.want, tc.failed, after, err)
			}
		})
	}
}
