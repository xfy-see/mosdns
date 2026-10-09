//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"strings"
	"testing"
)

func TestMinimalCacheRejectsDiskDumpBeforeDefaults(t *testing.T) {
	for _, args := range []*Args{{DumpFile: "cache.dump"}, {DumpInterval: 600}, {DumpInterval: -1}} {
		// Rejection happens before touching BP or changing args with defaults.
		before := *args
		if c, err := Init(nil, args); c != nil || err == nil || !strings.Contains(err.Error(), "full build") {
			t.Fatalf("unsupported args were not rejected: cache=%v err=%v", c, err)
		}
		if *args != before {
			t.Fatal("rejected args were changed by defaults")
		}
	}
}

func TestMinimalCacheKeepsMemoryAndLazyOptions(t *testing.T) {
	args := &Args{Size: 2048, LazyCacheTTL: 3600}
	c := NewCache(args, Opts{})
	defer c.Close()
	if args.DumpInterval != 0 || args.Size != 2048 || args.LazyCacheTTL != 3600 {
		t.Fatalf("memory cache options changed: %+v", args)
	}
}
