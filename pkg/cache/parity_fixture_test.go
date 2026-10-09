// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSharedCacheExpirationFixture(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/cache_backend.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Expired int64 `json:"expired_store_ms"`
		Live    int64 `json:"live_store_ms"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := New[testKey, int](Opts{Size: 64})
	defer c.Close()
	now := time.Now()
	c.Store(0, 7, now.Add(time.Duration(fixture.Expired)*time.Millisecond))
	if c.Len() != 0 {
		t.Fatal("expired store was retained")
	}
	c.Store(0, 9, now.Add(time.Duration(fixture.Live)*time.Millisecond))
	if v, _, ok := c.Get(0); !ok || v != 9 {
		t.Fatal("live entry missing")
	}
	c.gc(now.Add(time.Duration(fixture.Live+1) * time.Millisecond))
	if c.Len() != 0 {
		t.Fatal("GC retained expired entry")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing only stops the cleaner; explicit operations remain usable.
	c.Store(1, 11, now.Add(time.Minute))
	if v, _, ok := c.Get(1); !ok || v != 11 {
		t.Fatal("close disabled explicit cache operations")
	}
}
