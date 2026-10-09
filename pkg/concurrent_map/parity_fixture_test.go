// SPDX-License-Identifier: GPL-3.0-or-later
package concurrent_map

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedMapCapacityFixture(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/cache_backend.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Shards        int                                      `json:"shards"`
		CapacityCases []struct{ Size, Inserted, Expected int } `json:"capacity_cases"`
		CollisionKeys []testMapHashable                        `json:"collision_keys"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Shards != MapShardSize {
		t.Fatalf("shards %d", MapShardSize)
	}
	for _, c := range fixture.CapacityCases {
		m := NewMapCache[testMapHashable, int](c.Size)
		for i := 0; i < c.Inserted; i++ {
			m.Set(testMapHashable(i), i)
		}
		if m.Len() != c.Expected {
			t.Fatalf("size %d: len %d, want %d", c.Size, m.Len(), c.Expected)
		}
		m.Flush()
		if m.Len() != 0 {
			t.Fatal("flush retained entries")
		}
	}
	m := NewMapCache[testMapHashable, int](64)
	for i, key := range fixture.CollisionKeys {
		m.Set(key, i)
		if m.Len() != 1 {
			t.Fatal("colliding keys exceed shard capacity")
		}
		if value, ok := m.Get(key); !ok || value != i {
			t.Fatal("newest entry missing")
		}
	}
	// TestAndSet intentionally bypasses Set's capacity check in the original API.
	m.TestAndSet(0, func(int, bool) (int, bool, bool) { return 9, true, true })
	if value, ok := m.Get(0); !ok || value != 9 || m.Len() != 2 {
		t.Fatal("TestAndSet set/delete priority or capacity differs")
	}
}
