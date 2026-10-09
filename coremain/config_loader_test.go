package coremain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixed outputs were captured from the stage0 Viper implementation before its
// removal. Keeping an oracle in the test avoids retaining Viper as a test dependency.
func TestLoadConfigLegacyContract(t *testing.T) {
	cases := []struct{ name, file, input, want, errorPhase string }{
		{"yaml-basic", "test.yaml", "log: {level: error, production: true}\napi: {http: \"127.0.0.1:8080\"}\ninclude: [one.yml, two.json]\nplugins:\n- tag: main\n  type: sequence\n  args:\n  - exec: accept\n", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":true},\"Include\":[\"one.yml\",\"two.json\"],\"Plugins\":[{\"Tag\":\"main\",\"Type\":\"sequence\",\"Args\":[{\"exec\":\"accept\"}]}],\"API\":{\"HTTP\":\"127.0.0.1:8080\"}}", ""},
		{"yml-upper-keys-weak-values", "test.yml", "LoG: {LEVEL: ERROR, FILE: MixedCase.log, Production: \"true\"}\nAPI: {HTTP: 12345}\nINCLUDE: \"one.yml,two.json\"\nPLUGINS:\n- TAG: Main\n  TYPE: Sequence\n  ARGS: {PORT: \"53\", NESTED: [{KEY: MixedCase}], \"DOT.KEY\": Value}\n", "{\"Log\":{\"Level\":\"ERROR\",\"File\":\"MixedCase.log\",\"Production\":true},\"Include\":[\"one.yml\",\"two.json\"],\"Plugins\":[{\"Tag\":\"Main\",\"Type\":\"Sequence\",\"Args\":{\"dot.key\":\"Value\",\"nested\":[{\"key\":\"MixedCase\"}],\"port\":\"53\"}}],\"API\":{\"HTTP\":\"12345\"}}", ""},
		{"yaml-anchors", "test.yaml", "log: &log {level: error, production: true}\nplugins:\n- tag: main\n  type: test\n  args: {<<: *log, \"53\": value}\n", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":true},\"Include\":null,\"Plugins\":[{\"Tag\":\"main\",\"Type\":\"test\",\"Args\":{\"53\":\"value\",\"level\":\"error\",\"production\":true}}],\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-numeric-nested-keys", "test.yaml", "plugins: [{tag: main, type: test, args: {12: twelve, true: yes, null: zero}}]\n", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":[{\"Tag\":\"main\",\"Type\":\"test\",\"Args\":{\"\":\"zero\",\"12\":\"twelve\",\"true\":\"yes\"}}],\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-float-nested-keys", "test.yaml", "plugins: [{tag: main, type: test, args: {1e20: large, 1e-7: small}}]\n", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":[{\"Tag\":\"main\",\"Type\":\"test\",\"Args\":{\"0.0000001\":\"small\",\"100000000000000000000\":\"large\"}}],\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-empty-null", "test.yaml", "log: {}\napi: null\ninclude: []\nplugins: []\nunknown_null: null\nunknown_empty: {}\n", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":[],\"Plugins\":[],\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-empty-include", "test.yaml", "include: \"\"\nplugins: []\n", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":[],\"Plugins\":[],\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-dotted-root", "test.yaml", "log.level: error\napi.http: localhost:8090\ninclude: one.yml,two.json\n", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":false},\"Include\":[\"one.yml\",\"two.json\"],\"Plugins\":null,\"API\":{\"HTTP\":\"localhost:8090\"}}", ""},
		{"yaml-dotted-override", "test.yaml", "log: {level: warn}\nlog.level: error\n", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":null,\"API\":{\"HTTP\":\"\"}}", ""},
		{"json-basic", "test.json", "{\"log\":{\"level\":\"error\"},\"plugins\":[{\"tag\":\"main\",\"type\":\"test\",\"args\":{\"size\":12.5,\"Nested\":[{\"UPPER\":\"MixedCase\"}]}}],\"include\":[\"one.yml\"]}", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":false},\"Include\":[\"one.yml\"],\"Plugins\":[{\"Tag\":\"main\",\"Type\":\"test\",\"Args\":{\"nested\":[{\"upper\":\"MixedCase\"}],\"size\":12.5}}],\"API\":{\"HTTP\":\"\"}}", ""},
		{"json-dotted-keys", "test.json", "{\"LOG.LEVEL\":\"debug\",\"api.http\":\"127.0.0.1:8080\",\"include\":\"one.yml,two.json\"}", "{\"Log\":{\"Level\":\"debug\",\"File\":\"\",\"Production\":false},\"Include\":[\"one.yml\",\"two.json\"],\"Plugins\":null,\"API\":{\"HTTP\":\"127.0.0.1:8080\"}}", ""},
		{"json-null", "test.json", "null", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":null,\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-empty", "test.yaml", "", "{\"Log\":{\"Level\":\"\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":null,\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-multiple-documents", "test.yaml", "log: {level: error}\n---\nunknown: ignored\n", "{\"Log\":{\"Level\":\"error\",\"File\":\"\",\"Production\":false},\"Include\":null,\"Plugins\":null,\"API\":{\"HTTP\":\"\"}}", ""},
		{"yaml-unknown", "test.yaml", "unexpected: true\n", "", "decode"},
		{"yaml-log-unknown", "test.yaml", "log: {level: error, unused: true}\n", "", "decode"},
		{"yaml-api-unknown", "test.yaml", "api: {http: localhost, unused: true}\n", "", "decode"},
		{"yaml-plugin-unknown", "test.yaml", "plugins: [{tag: main, type: test, unused: true}]\n", "", "decode"},
		{"yaml-invalid-bool", "test.yaml", "log: {production: not-a-bool}\n", "", "decode"},
		{"yaml-malformed", "test.yaml", "plugins: [\n", "", "read"},
		{"yaml-duplicate-key", "test.yaml", "log: {level: error, level: warn}\n", "", "read"},
		{"yaml-root-list", "test.yaml", "- item\n", "", "read"},
		{"json-malformed", "test.json", "{\"log\":", "", "read"},
		{"json-root-list", "test.json", "[]", "", "read"},
		{"json-empty", "test.json", "", "", "read"},
		{"yaml-uppercase-extension", "test.YAML", "log: {level: error}\n", "", "read"},
		{"json-number-weak-string", "test.json", "{\"log\":{\"level\":42,\"production\":\"false\"},\"api\":{\"http\":53},\"include\":1}", "{\"Log\":{\"Level\":\"42\",\"File\":\"\",\"Production\":false},\"Include\":[\"1\"],\"Plugins\":null,\"API\":{\"HTTP\":\"53\"}}", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile(tc.file, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, used, err := loadConfig(tc.file)
			if tc.errorPhase != "" {
				prefix := "failed to read config:"
				if tc.errorPhase == "decode" {
					prefix = "failed to unmarshal config:"
				}
				if err == nil || !strings.HasPrefix(err.Error(), prefix) || cfg != nil || used != "" {
					t.Fatalf("cfg=%v file=%q error=%v, want %s", cfg, used, err, prefix)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if used != tc.file {
				t.Fatalf("path=%q, want %q", used, tc.file)
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tc.want {
				t.Fatalf("config=%s, want %s", raw, tc.want)
			}
		})
	}
}

func TestLoadConfigDefaultSearchOrderAndPaths(t *testing.T) {
	for _, names := range [][]string{{"config.yml"}, {"config.yaml", "config.yml"}, {"config.json", "config.yaml", "config.yml"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			t.Chdir(t.TempDir())
			// Unrelated names and directories must not be treated as the default config.
			if err := os.Mkdir("config.backup.yaml", 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				body := "log: {level: error}\n"
				if strings.HasSuffix(name, ".json") {
					body = `{"log":{"level":"error"}}`
				}
				if err := os.WriteFile(name, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, used, err := loadConfig("")
			if err != nil {
				t.Fatal(err)
			}
			want, err := filepath.Abs(names[0])
			if err != nil {
				t.Fatal(err)
			}
			if used != want || cfg.Log.Level != "error" {
				t.Fatalf("used=%q cfg=%+v", used, cfg)
			}
		})
	}
	t.Run("skip-directory", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.Mkdir("config.json", 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("config.yaml", []byte("log: {level: error}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, used, err := loadConfig("")
		if err != nil || filepath.Base(used) != "config.yaml" {
			t.Fatalf("file=%q err=%v", used, err)
		}
	})
}

func TestLoadConfigFixtureAndArgumentNumberTypes(t *testing.T) {
	cfg, _, err := loadConfig("../tests/fixtures/split.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != "1e5c18fbf76f0863574bc7448d5c9d483a11b681b4e3933483245c1b5b21c63c" {
		t.Fatalf("existing split fixture config SHA=%s", got)
	}
	for _, tc := range []struct {
		name, body string
		integer    bool
	}{{"typed.yaml", "plugins: [{tag: test, type: test, args: {value: 7}}]", true}, {"typed.json", `{"plugins":[{"tag":"test","type":"test","args":{"value":7}}]}`, false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile(tc.name, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, _, err := loadConfig(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			value := cfg.Plugins[0].Args.(map[string]any)["value"]
			if tc.integer {
				if _, ok := value.(int); !ok {
					t.Fatalf("YAML number type=%T", value)
				}
			} else if _, ok := value.(float64); !ok {
				t.Fatalf("JSON number type=%T", value)
			}
		})
	}
}

func TestLoadConfigIncludeBeforePluginsFromWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("nested", 0700); err != nil {
		t.Fatal(err)
	}
	typ := "test_config_include_order"
	type args struct {
		Value string `yaml:"value"`
		Ref   string `yaml:"ref"`
	}
	RegNewPluginFunc(typ, func(bp *BP, a any) (any, error) {
		x := a.(*args)
		if x.Ref != "" {
			value := bp.M().GetPlugin(x.Ref)
			if value == nil {
				return nil, fmt.Errorf("included plugin %s missing", x.Ref)
			}
			return value, nil
		}
		return x.Value, nil
	}, func() any { return new(args) })
	t.Cleanup(func() { DelPluginType(typ) })
	included := `{"plugins":[{"tag":"included","type":"test_config_include_order","args":{"VALUE":123}}]}`
	main := "include: included.json\nplugins: [{tag: main, type: test_config_include_order, args: {REF: included}}]\n"
	for name, body := range map[string]string{"included.json": included, "nested/main.yml": main} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, used, err := loadConfig("nested/main.yml")
	if err != nil || used != "nested/main.yml" {
		t.Fatalf("file=%q err=%v", used, err)
	}
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	if err := m.loadPluginsFromCfg(cfg, 0); err != nil {
		t.Fatal(err)
	}
	if m.GetPlugin("included") != "123" || m.GetPlugin("main") != "123" {
		t.Fatalf("include/order/weak args changed: %#v", m.plugins)
	}
	if err := os.Remove("included.json"); err != nil {
		t.Fatal(err)
	}
	m = NewTestMosdnsWithPlugins(make(map[string]any))
	if err := m.loadPluginsFromCfg(cfg, 0); err == nil || !strings.Contains(err.Error(), "included.json") {
		t.Fatalf("missing include error=%v", err)
	}
}

func TestLoadConfigReadFailures(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, path := range []string{"", "missing.yaml", "."} {
		if cfg, used, err := loadConfig(path); err == nil || cfg != nil || used != "" || !strings.HasPrefix(err.Error(), "failed to read config:") {
			t.Fatalf("path=%q cfg=%v file=%q err=%v", path, cfg, used, err)
		}
	}
}

func TestLoadConfigRejectsRemovedFormats(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, ext := range []string{"toml", "ini", "hcl", "tfvars", "properties", "props", "prop", "dotenv", "env"} {
		name := "config." + ext
		if err := os.WriteFile(name, []byte("[log]\nlevel = \"error\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if cfg, used, err := loadConfig(name); err == nil || cfg != nil || used != "" || !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("removed format %s: cfg=%v file=%q error=%v", ext, cfg, used, err)
		}
	}
	if _, _, err := loadConfig(""); err == nil {
		t.Fatal("default search accepted a removed format")
	}
	if err := os.WriteFile("config.yaml", []byte("log: {level: error}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, used, err := loadConfig(""); err != nil || filepath.Base(used) != "config.yaml" {
		t.Fatalf("removed formats blocked YAML search: file=%q error=%v", used, err)
	}
}

func TestLoadConfigIncludeDepthBound(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("recursive.yaml", []byte("include: recursive.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := loadConfig("recursive.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	if err := m.loadPluginsFromCfg(cfg, 0); err == nil || !strings.Contains(err.Error(), "maximum include depth reached") {
		t.Fatalf("recursive include error=%v", err)
	}
}
