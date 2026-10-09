//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package doh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

type ownershipRoundTripper struct {
	wire       []byte
	bodyClosed chan struct{}
}

func (rt *ownershipRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &ownershipResponseBody{Reader: bytes.NewReader(rt.wire), closed: rt.bodyClosed}}, nil
}
func (rt *ownershipRoundTripper) Close() error { return nil }

type ownershipResponseBody struct {
	*bytes.Reader
	closed chan struct{}
}

func (b *ownershipResponseBody) Close() error {
	if b.closed != nil {
		close(b.closed)
	}
	return nil
}

// Pause the outer consumer's select so a completed reply and cancellation are
// both ready when it is allowed to proceed. Every Done caller observes one gate.
type ownershipGateContext struct {
	context.Context
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (c *ownershipGateContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered); <-c.proceed })
	return c.Context.Done()
}

type ownershipPoolTracker struct {
	mu                 sync.Mutex
	responseSize       int
	produced           int
	released           int
	outstanding        map[*[]byte]int
	allocationReady    chan struct{}
	continueAllocation chan struct{}
}

func ownershipTrackPool(t *testing.T, responseSize int, ready, proceed chan struct{}) *ownershipPoolTracker {
	t.Helper()
	tracker := &ownershipPoolTracker{responseSize: responseSize, outstanding: make(map[*[]byte]int), allocationReady: ready, continueAllocation: proceed}
	originalGet, originalRelease := pool.GetBuf, pool.ReleaseBuf
	pool.GetBuf = func(size int) *[]byte {
		b := originalGet(size)
		if size == tracker.responseSize {
			tracker.mu.Lock()
			tracker.produced++
			tracker.outstanding[b]++
			tracker.mu.Unlock()
			if tracker.allocationReady != nil {
				close(tracker.allocationReady)
				<-tracker.continueAllocation
			}
		}
		return b
	}
	pool.ReleaseBuf = func(b *[]byte) {
		tracker.mu.Lock()
		if tracker.outstanding[b] > 0 {
			tracker.released++
			tracker.outstanding[b]--
			if tracker.outstanding[b] == 0 {
				delete(tracker.outstanding, b)
			}
		}
		tracker.mu.Unlock()
		originalRelease(b)
	}
	t.Cleanup(func() {
		pool.GetBuf, pool.ReleaseBuf = originalGet, originalRelease
		// Keep the deliberately failing before-fix diagnostic from polluting the pool.
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		for b := range tracker.outstanding {
			originalRelease(b)
		}
	})
	return tracker
}
func (tracker *ownershipPoolTracker) requireReturned(t *testing.T, expected int) {
	t.Helper()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.produced != expected || tracker.released != expected || len(tracker.outstanding) != 0 {
		t.Fatalf("response buffers produced=%d released=%d outstanding=%d; want %d exactly-once returns", tracker.produced, tracker.released, len(tracker.outstanding), expected)
	}
}
func ownershipFixtureWire(t *testing.T) ([]byte, []byte) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("owned-buffer.test.", dns.TypeTXT)
	q.Id = 0x1234
	query, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r := new(dns.Msg)
	r.SetReply(q)
	r.Id = 0
	r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 200)}}}
	reply, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query, reply
}

func TestCanceledCallerReturnsDetachedResponseBuffer(t *testing.T) {
	query, reply := ownershipFixtureWire(t)
	ready, proceed := make(chan struct{}), make(chan struct{})
	tracker := ownershipTrackPool(t, len(reply), ready, proceed)
	u, err := NewUpstream("https://fixture.invalid/dns-query", &ownershipRoundTripper{wire: reply}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		b, err := u.ExchangeContext(ctx, query)
		if b != nil {
			pool.ReleaseBuf(b)
		}
		finished <- err
	}()
	<-ready
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation changed: %v", err)
	}
	close(proceed)
	_ = u.Close()
	tracker.requireReturned(t, 1)
}

func TestCancellationAndResponseReadyTogetherReturnsEveryBuffer(t *testing.T) {
	query, reply := ownershipFixtureWire(t)
	tracker := ownershipTrackPool(t, len(reply), nil, nil)
	const attempts = 256
	for i := 0; i < attempts; i++ {
		bodyClosed := make(chan struct{})
		u, err := NewUpstream("https://fixture.invalid/dns-query", &ownershipRoundTripper{wire: reply, bodyClosed: bodyClosed}, nil)
		if err != nil {
			t.Fatal(err)
		}
		base, cancel := context.WithCancel(context.Background())
		ctx := &ownershipGateContext{Context: base, entered: make(chan struct{}), proceed: make(chan struct{})}
		finished := make(chan error, 1)
		go func() {
			b, err := u.ExchangeContext(ctx, query)
			if b != nil {
				pool.ReleaseBuf(b)
			}
			finished <- err
		}()
		<-ctx.entered
		<-bodyClosed
		cancel()
		close(ctx.proceed)
		err = <-finished
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected simultaneous result: %v", err)
		}
		_ = u.Close()
	}
	tracker.requireReturned(t, attempts)
}

var _ io.ReadCloser = (*ownershipResponseBody)(nil)
