package coremain

import (
	"errors"
	"strings"
	"testing"
)

func TestCustomPluginRegistrationInitLookupAndDelete(t *testing.T) {
	name := "test_custom_registry"
	type args struct{ Value int }
	RegNewPluginFunc(name, func(bp *BP, a any) (any, error) {
		if bp.Tag() != "custom" {
			t.Fatalf("factory tag = %q", bp.Tag())
		}
		return a.(*args).Value, nil
	}, func() any { return new(args) })
	defer DelPluginType(name)
	if _, ok := GetPluginType(name); !ok {
		t.Fatal("registered factory missing")
	}
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	if err := m.newPlugin(PluginConfig{Tag: "custom", Type: name, Args: map[string]any{"value": "7"}}); err != nil {
		t.Fatal(err)
	}
	if got := m.GetPlugin("custom"); got != 7 {
		t.Fatalf("plugin = %v", got)
	}
	if err := m.newPlugin(PluginConfig{Tag: "custom", Type: name}); err == nil || !strings.Contains(err.Error(), "duplicated plugin tag") {
		t.Fatalf("duplicate tag error = %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("duplicate registration did not panic")
			}
		}()
		RegNewPluginFunc(name, nil, nil)
	}()
	DelPluginType(name)
	DelPluginType(name)
	if _, ok := GetPluginType(name); ok {
		t.Fatal("deleted type is still registered")
	}
	if err := m.newPlugin(PluginConfig{Tag: "missing", Type: name}); err == nil {
		t.Fatal("unknown type was accepted")
	}
}

func TestCustomFactoryErrorsPropagate(t *testing.T) {
	name := "test_custom_registry_error"
	want := errors.New("factory error")
	RegNewPluginFunc(name, func(*BP, any) (any, error) { return nil, want }, func() any { return new(struct{}) })
	defer DelPluginType(name)
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	err := m.newPlugin(PluginConfig{Tag: "broken", Type: name})
	if !errors.Is(err, want) {
		t.Fatalf("factory error = %v", err)
	}
}
