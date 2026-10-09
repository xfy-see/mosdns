//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package plugin

import (
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"reflect"
	"sort"
	"testing"
)

func TestMinimalProfilePluginBoundary(t *testing.T) {
	got := coremain.GetAllPluginTypes()
	sort.Strings(got)
	want := []string{"cache", "domain_set", "forward", "sequence", "tcp_server", "udp_server"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("minimal plugin registry = %v, want %v", got, want)
	}
	for _, typ := range []string{"qname", "has_resp"} {
		if sequence.GetMatchQuickSetup(typ) == nil {
			t.Fatalf("required matcher %s missing", typ)
		}
	}
	if sequence.GetExecQuickSetup("nftset") == nil {
		t.Fatal("required nftset executable missing")
	}
	for _, typ := range []string{"ipset", "arbitrary", "fallback", "ecs"} {
		if sequence.GetExecQuickSetup(typ) != nil {
			t.Fatalf("full-only executable %s linked into minimal registry", typ)
		}
	}
	for _, typ := range []string{"resp_ip", "qclass", "random"} {
		if sequence.GetMatchQuickSetup(typ) != nil {
			t.Fatalf("full-only matcher %s linked into minimal registry", typ)
		}
	}
}
