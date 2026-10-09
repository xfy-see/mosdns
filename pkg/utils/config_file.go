// SPDX-License-Identifier: GPL-3.0-or-later
package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ReadConfigMap reads the supported configuration formats and preserves the
// previous loader's case-insensitive, dotted-key settings representation.
func ReadConfigMap(filename string) (map[string]any, error) {
	format := strings.TrimPrefix(filepath.Ext(filename), ".")
	if format != "yaml" && format != "yml" && format != "json" {
		return nil, fmt.Errorf("unsupported format %q; use yaml, yml or json", format)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return DecodeConfigMap(data, format)
}

// DecodeConfigMap parses a YAML/YML or JSON document without accepting other formats.
func DecodeConfigMap(data []byte, format string) (map[string]any, error) {
	values := make(map[string]any)
	var err error
	switch format {
	case "yaml", "yml":
		err = yaml.Unmarshal(data, &values)
	case "json":
		err = json.Unmarshal(data, &values)
	default:
		return nil, fmt.Errorf("unsupported format %q; use yaml, yml or json", format)
	}
	if err != nil {
		return nil, err
	}
	return normalizeConfigMap(values), nil
}

// EncodeConfigMap uses the same YAML and JSON encoders as the previous loader.
func EncodeConfigMap(values map[string]any, format string) ([]byte, error) {
	switch format {
	case "yaml", "yml":
		return yaml.Marshal(values)
	case "json":
		return json.MarshalIndent(values, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format %q; use yaml, yml or json", format)
	}
}

func normalizeConfigMap(values map[string]any) map[string]any {
	// Retain the former case-insensitive keys, including maps within plugin
	// argument arrays. Values and dotted keys inside those arrays stay intact.
	var normalize func(any) any
	normalize = func(value any) any {
		switch value := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(value))
			for key, v := range value {
				out[strings.ToLower(key)] = normalize(v)
			}
			return out
		case map[any]any:
			out := make(map[string]any, len(value))
			for key, v := range value {
				name := ""
				switch key := key.(type) {
				case nil:
				case float64:
					name = strconv.FormatFloat(key, 'f', -1, 64)
				case float32:
					name = strconv.FormatFloat(float64(key), 'f', -1, 32)
				default:
					name = fmt.Sprint(key)
				}
				out[strings.ToLower(name)] = normalize(v)
			}
			return out
		case []any:
			for i := range value {
				value[i] = normalize(value[i])
			}
		}
		return value
	}
	values = normalize(values).(map[string]any)

	// The previous loader expanded dotted map keys and omitted nil/empty-map
	// leaves outside arrays. A literal dotted key takes precedence over the
	// same path expressed as a nested map.
	keys := make(map[string]struct{})
	var collect func(map[string]any, string)
	collect = func(m map[string]any, prefix string) {
		for key, value := range m {
			key = prefix + key
			if nested, ok := value.(map[string]any); ok {
				collect(nested, key+".")
			} else {
				keys[key] = struct{}{}
			}
		}
	}
	collect(values, "")
	var lookup func(map[string]any, []string) any
	lookup = func(m map[string]any, path []string) any {
		for i := len(path); i > 0; i-- {
			value := m[strings.Join(path[:i], ".")]
			if i == len(path) && value != nil {
				return value
			}
			if nested, ok := value.(map[string]any); ok {
				if found := lookup(nested, path[i:]); found != nil {
					return found
				}
			}
		}
		return nil
	}
	settings := make(map[string]any)
	for key := range keys {
		path := strings.Split(key, ".")
		value := lookup(values, path)
		if value == nil {
			continue
		}
		m := settings
		for _, part := range path[:len(path)-1] {
			nested, ok := m[part].(map[string]any)
			if !ok {
				nested = make(map[string]any)
				m[part] = nested
			}
			m = nested
		}
		m[path[len(path)-1]] = value
	}
	return settings
}
