package concurrent_map

import (
	"sync"
	"testing"
	"time"
)

func TestFullShardUpdateDoesNotEvict(t *testing.T) {
	m := NewMapCache[testMapHashable, int](MapShardSize * 2)
	m.Set(0, 1)
	m.Set(MapShardSize, 2)
	// The eviction victim is intentionally unspecified. Repeated updates must
	// preserve both entries, regardless of which key a map iteration would pick.
	for i := 0; i < 256; i++ {
		m.Set(0, i)
		if got, ok := m.Get(MapShardSize); !ok || got != 2 {
			t.Fatal("updating an existing key evicted another entry")
		}
		if got, ok := m.Get(0); !ok || got != i || m.Len() != 2 {
			t.Fatal("updating an existing key changed the shard size or lost its value")
		}
	}
}

func TestFlushRequiresExclusiveShardLock(t *testing.T) {
	s := newShard[int, int](0)
	s.set(1, 2)
	s.l.RLock()
	done := make(chan struct{})
	go func() {
		s.flush()
		close(done)
	}()
	select {
	case <-done:
		s.l.RUnlock()
		t.Fatal("flush modified the map while another reader held the lock")
	case <-time.After(20 * time.Millisecond):
	}
	s.l.RUnlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flush did not finish after the reader released the lock")
	}
	if s.len() != 0 {
		t.Fatal("flush retained entries")
	}
}

func TestConcurrentFlushGetSet(t *testing.T) {
	m := NewMap[testMapHashable, int]()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				m.Set(0, i)
				m.Get(0)
				m.Len()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			m.Flush()
		}
	}()
	wg.Wait()
}

func BenchmarkBoundedMapOverwrite(b *testing.B) {
	const size = MapShardSize * 16
	m := NewMapCache[testMapHashable, int](size)
	for i := 0; i < size; i++ {
		m.Set(testMapHashable(i), i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Set(testMapHashable(i%size), i)
	}
}
