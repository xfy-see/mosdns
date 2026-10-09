package query_context

import (
	"github.com/miekg/dns"
	"testing"
)

func TestRegisteredKeysCopyIndependentMapSharedValues(t *testing.T) {
	a, b := RegKey(), RegKey()
	if a == 0 || b == 0 || a == b {
		t.Fatal("registered keys must be unique and nonzero")
	}
	q := new(dns.Msg)
	q.SetQuestion("registry.example.", dns.TypeA)
	original := NewContext(q)
	if _, ok := original.GetValue(a); ok {
		t.Fatal("new query has a value")
	}
	value := new(int)
	*value = 3
	original.StoreValue(a, value)
	original.StoreValue(b, "original")
	copied := original.Copy()
	shared, _ := copied.GetValue(a)
	*shared.(*int) = 9
	got, _ := original.GetValue(a)
	if *got.(*int) != 9 {
		t.Fatal("Copy deep-copied the stored value")
	}
	copied.StoreValue(b, "copy")
	copied.DeleteValue(a)
	if _, ok := original.GetValue(a); !ok {
		t.Fatal("Copy shares the map")
	}
	if _, ok := copied.GetValue(a); ok {
		t.Fatal("DeleteValue did not remove key")
	}
	got, _ = original.GetValue(b)
	if got != "original" {
		t.Fatal("Copy overwrite changed source map")
	}
	fresh := NewContext(q.Copy())
	if _, ok := fresh.GetValue(b); ok {
		t.Fatal("KV leaked to another query")
	}
}
