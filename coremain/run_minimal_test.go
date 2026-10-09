//go:build mosdns_minimal

package coremain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalCheckDoesNotInitializePlugins(t *testing.T) {
	const typ = "test_minimal_check_no_init"
	type args struct {
		Value string `yaml:"value"`
	}
	initialized := false
	RegNewPluginFunc(typ, func(*BP, any) (any, error) {
		initialized = true
		return nil, nil
	}, func() any { return new(args) })
	t.Cleanup(func() { DelPluginType(typ) })
	t.Chdir(t.TempDir())
	if err := os.WriteFile("config.yaml", []byte("plugins: [{type: "+typ+", args: {value: ok}}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkMinimalConfig("config.yaml", 0); err != nil {
		t.Fatal(err)
	}
	if initialized {
		t.Fatal("configuration check initialized a plugin")
	}
	if err := os.WriteFile("config.yaml", []byte("plugins: [{type: "+typ+", args: {unknown: true}}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkMinimalConfig("config.yaml", 0); err == nil {
		t.Fatal("configuration check accepted an unknown plugin option")
	}
	if initialized {
		t.Fatal("invalid configuration check initialized a plugin")
	}
}

func TestMinimalAPIRejectedBeforeLoggerOrPlugins(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "must-not-be-created.log")
	cfg := &Config{API: APIConfig{HTTP: "127.0.0.1:0"}}
	cfg.Log.File = file
	if m, err := NewMosdns(cfg); err == nil || m != nil || !strings.Contains(err.Error(), "HTTP API") {
		t.Fatalf("instance=%v error=%v", m, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("logger was opened for an unsupported config: %v", err)
	}
	// Included configs must reject API settings too, rather than silently ignore them.
	t.Chdir(dir)
	if err := os.WriteFile("include.yaml", []byte("api: {http: '127.0.0.1:0'}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("config.yaml", []byte("include: [include.yaml]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkMinimalConfig("config.yaml", 0); err == nil || !strings.Contains(err.Error(), "HTTP API") {
		t.Fatalf("check error=%v", err)
	}
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	if err := m.loadPluginsFromCfg(&Config{Include: []string{"include.yaml"}}, 0); err == nil || !strings.Contains(err.Error(), "HTTP API") {
		t.Fatalf("startup include error=%v", err)
	}
}

func TestMinimalUnsupportedCLIAndConfig(t *testing.T) {
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	for _, args := range [][]string{{"service", "install"}, {"config", "gen"}, {"start", "--unknown"}, {"start", "extra"}, {"version", "extra"}} {
		os.Args = append([]string{"mosdns"}, args...)
		if err := Run(); err == nil {
			t.Fatalf("CLI accepted %v", args)
		}
	}
	t.Chdir(t.TempDir())
	for _, body := range []string{"plugins: [{type: http_server}]\n", "include: [config.yaml]\n"} {
		if err := os.WriteFile("config.yaml", []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkMinimalConfig("config.yaml", 0); err == nil {
			t.Fatalf("check accepted %s", body)
		}
	}
}
