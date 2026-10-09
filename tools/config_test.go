// SPDX-License-Identifier: GPL-3.0-or-later
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Exact output hashes, error outcomes and file modes were captured from stage0
// Viper config conv/gen before its removal.
func TestConfigToolsLegacyOutputAndModes(t *testing.T) {
	t.Chdir(t.TempDir())
	input := []byte("LoG: {LEVEL: error}\nAPI.HTTP: 127.0.0.1:8080\nPLUGINS: [{TAG: Main, TYPE: Test, ARGS: {CaseKey: CaseValue, PORT: 53}}]\nNULL_KEY: null\nEMPTY_MAP: {}\n")
	if err := os.WriteFile("in.yaml", input, 0600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"existing-conv.json": "keep", "existing-gen.json": "old"} {
		if err := os.WriteFile(name, []byte(body), 0640); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, sha string
		mode      os.FileMode
		failed    bool
	}{
		{"conv.json", "a290ba750d7e8d06383137021ecd6161f733c987ce6ee329f238e174e0e73898", 0644, false},
		{"conv.yaml", "2b98a72199f97687444287966b69962c9cd80c07b95dc39c8fafa379db164840", 0644, false},
		{"conv.yml", "2b98a72199f97687444287966b69962c9cd80c07b95dc39c8fafa379db164840", 0644, false},
		{"conv", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 00, true},
		{"gen.json", "eb0e025d6f329496e698fe8dcd0a6b923889b58fe61200cb6dc202cac58d4d99", 0644, false},
		{"gen.yaml", "412a58d88f02e1536ff23938bd5dd3c9f30b2d07977514dddd79d8c07e63b049", 0644, false},
		{"gen.yml", "412a58d88f02e1536ff23938bd5dd3c9f30b2d07977514dddd79d8c07e63b049", 0644, false},
		{"gen", "412a58d88f02e1536ff23938bd5dd3c9f30b2d07977514dddd79d8c07e63b049", 0644, false},
		{"existing-conv.json", "6ca7ea2feefc88ecb5ed6356ed963f47dc9137f82526fdd25d618ea626d0803f", 0640, true},
		{"existing-gen.json", "eb0e025d6f329496e698fe8dcd0a6b923889b58fe61200cb6dc202cac58d4d99", 0640, false},
		{"uppercase.YAML", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 00, true},
	}
	for _, tc := range cases {
		var err error
		if strings.HasPrefix(tc.name, "conv") || strings.HasPrefix(tc.name, "existing-conv") {
			err = convCfg("in.yaml", tc.name)
		} else {
			err = genCfg(tc.name)
		}
		if (err != nil) != tc.failed {
			t.Fatalf("%s error=%v, want failed=%v", tc.name, err, tc.failed)
		}
		info, statErr := os.Stat(tc.name)
		if tc.mode == 0 {
			if !os.IsNotExist(statErr) {
				t.Fatalf("%s unexpectedly created: %v", tc.name, statErr)
			}
			continue
		}
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != tc.mode {
			t.Fatalf("%s mode=%o, want %o", tc.name, info.Mode().Perm(), tc.mode)
		}
		data, err := os.ReadFile(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != tc.sha {
			t.Fatalf("%s output SHA=%s, want %s", tc.name, got, tc.sha)
		}
	}
}

func TestConfigCommandsPreserveFlagsAndArguments(t *testing.T) {
	conv := newConvCmd()
	if conv.Use != "conv -i input_cfg -o output_cfg" || conv.Flags().Lookup("in").Shorthand != "i" || conv.Flags().Lookup("out").Shorthand != "o" {
		t.Fatal("conversion CLI changed")
	}
	if err := conv.Args(conv, []string{"extra"}); err == nil {
		t.Fatal("conversion accepted positional argument")
	}
	gen := newGenCmd()
	if gen.Use != "gen config_file" {
		t.Fatal("generation CLI changed")
	}
	for _, args := range [][]string{nil, {"one", "two"}} {
		if err := gen.Args(gen, args); err == nil {
			t.Fatal("generation accepted wrong argument count")
		}
	}
	if err := gen.Args(gen, []string{"one"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conv.Short, "yaml, yml, json") || !strings.Contains(gen.Short, "yaml, yml, json") || strings.Contains(conv.Short, "toml") {
		t.Fatal("supported-format help differs")
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("in.yml", []byte("log: {level: error}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conv.SetArgs([]string{"-i", "in.yml", "-o", "out.json"})
	if err := conv.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("out.json"); err != nil {
		t.Fatal(err)
	}
	gen.SetArgs([]string{"template.yml"})
	if err := gen.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("template.yml"); err != nil {
		t.Fatal(err)
	}
}

func TestConfigConversionDoesNotOverwriteConcurrentTarget(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.yaml")
	out := filepath.Join(dir, "output.json")
	if err := os.WriteFile(in, []byte("log: {level: error}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- convCfg(in, out) }()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, failures := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d, want one exclusive creator", successes, failures)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := convCfg(in, out); err == nil {
		t.Fatal("existing target overwritten")
	}
	after, err := os.ReadFile(out)
	if err != nil || string(after) != string(before) {
		t.Fatal("existing target changed")
	}
}

func TestConfigToolsRejectRemovedFormatsAndPreserveTargets(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("input.yaml", []byte("log: {level: error}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"toml", "ini", "hcl", "tfvars", "properties", "props", "prop", "dotenv", "env"} {
		out := "output." + ext
		if err := genCfg(out); err == nil {
			t.Fatalf("generation accepted %s", ext)
		}
		if err := convCfg("input.yaml", out); err == nil {
			t.Fatalf("conversion accepted %s", ext)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("unsupported output %s created", out)
		}
		in := "input." + ext
		if err := os.WriteFile(in, []byte("log: {level: error}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := convCfg(in, "output.json"); err == nil {
			t.Fatalf("conversion accepted input %s", ext)
		}
	}
	if err := os.WriteFile("broken.json", []byte(`{"log":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := convCfg("broken.json", "broken-output.yaml"); err == nil {
		t.Fatal("bad JSON accepted")
	}
	if _, err := os.Stat("broken-output.yaml"); !os.IsNotExist(err) {
		t.Fatal("bad input created output")
	}
	if err := genCfg("missing/template.yaml"); err == nil {
		t.Fatal("missing output directory accepted")
	}
}
