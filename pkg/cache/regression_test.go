package cache

import (
	"testing"
	"time"
)

// The hook schedules a fresh write exactly between the first lookup and the
// expired entry's removal, without sleeps or relying on goroutine timing.
type interleavedKey struct {
	id   uint64
	hook *func()
}

func (k interleavedKey) Sum() uint64 {
	if k.hook != nil {
		(*k.hook)()
	}
	return k.id
}

func TestExpiredLookupDoesNotDeleteConcurrentReplacement(t *testing.T) {
	c := New[interleavedKey, string](Opts{})
	defer c.Close()
	calls := 0
	var k interleavedKey
	hook := func() {
		calls++
		if calls == 2 {
			c.Store(k, "fresh", time.Now().Add(time.Hour))
		}
	}
	k = interleavedKey{id: 1, hook: &hook}
	c.m.Set(k, &elem[string]{v: "expired", expirationTime: time.Now().Add(-time.Second)})
	calls = 0
	if _, _, ok := c.Get(k); ok {
		t.Fatal("expired lookup should miss")
	}
	if got, _, ok := c.Get(k); !ok || got != "fresh" {
		t.Fatal("expired lookup deleted the replacement stored during removal")
	}
}
