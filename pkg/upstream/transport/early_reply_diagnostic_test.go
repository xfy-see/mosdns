// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

type watchedResponse struct {
	owner  *responseBufferWatch
	active bool
}

var responseReleaseWatch = struct {
	sync.Mutex
	owners map[*byte]watchedResponse
}{owners: make(map[*byte]watchedResponse)}

// Install once before tests start. Replacing exported pool functions during
// individual tests would race with older tests' background connection cleanup.
func TestMain(m *testing.M) {
	get, release := pool.GetBuf, pool.ReleaseBuf
	pool.GetBuf = func(size int) *[]byte {
		b := get(size)
		if len(*b) > 0 {
			responseReleaseWatch.Lock()
			key := &(*b)[0]
			if owner, ok := responseReleaseWatch.owners[key]; ok {
				// A later borrow of this backing buffer is not a response until
				// a successful synthetic Read records it. In particular, EOF
				// cleanup of a reused receive buffer is not a double release.
				owner.active = false
				responseReleaseWatch.owners[key] = owner
			}
			responseReleaseWatch.Unlock()
		}
		return b
	}
	pool.ReleaseBuf = func(b *[]byte) {
		if len(*b) > 0 {
			responseReleaseWatch.Lock()
			if owner := responseReleaseWatch.owners[&(*b)[0]]; owner.active {
				owner.owner.released++
			}
			responseReleaseWatch.Unlock()
		}
		release(b)
	}
	os.Exit(m.Run())
}

type responseBufferWatch struct {
	read, released int
	keys           map[*byte]struct{}
}

func newResponseBufferWatch(t *testing.T) *responseBufferWatch {
	w := &responseBufferWatch{keys: make(map[*byte]struct{})}
	t.Cleanup(func() {
		responseReleaseWatch.Lock()
		defer responseReleaseWatch.Unlock()
		for key := range w.keys {
			if responseReleaseWatch.owners[key].owner == w {
				delete(responseReleaseWatch.owners, key)
			}
		}
	})
	return w
}

func (w *responseBufferWatch) record(b []byte) {
	responseReleaseWatch.Lock()
	defer responseReleaseWatch.Unlock()
	w.read++
	w.keys[&b[0]] = struct{}{}
	responseReleaseWatch.owners[&b[0]] = watchedResponse{owner: w, active: true}
}

func (w *responseBufferWatch) assertReleased(t *testing.T, want int) {
	t.Helper()
	responseReleaseWatch.Lock()
	defer responseReleaseWatch.Unlock()
	if w.read != want || w.released != want {
		t.Fatalf("response buffer ownership: read=%d released=%d, want exactly %d", w.read, w.released, want)
	}
}

func earlyReplyQuery(t *testing.T) ([]byte, *dns.Msg) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("early-reply.test.", dns.TypeAAAA)
	q.Id = 0x1234
	q.SetEdns0(1232, true)
	payload, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload, q
}

func TestEarlyReplyDeliveredBeforeWriteReturns(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		name := "udp"
		if tcp {
			name = "tcp"
		}
		t.Run(name, func(t *testing.T) {
			watch := newResponseBufferWatch(t)
			c := newEarlyReplyConn(tcp, watch)
			dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: tcp}, c)
			defer dc.Close()
			<-c.beforeRead
			payload, q := earlyReplyQuery(t)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			r, err := dc.exchange(ctx, payload)
			if err != nil {
				t.Fatalf("first reply dispatched before Write returned was lost: %v", err)
			}
			var reply dns.Msg
			unpackErr := reply.Unpack(*r)
			pool.ReleaseBuf(r)
			if unpackErr != nil || reply.Id != q.Id || reply.Rcode != dns.RcodeRefused || !reply.Response || reply.Question[0] != q.Question[0] || reply.IsEdns0() == nil || !reply.IsEdns0().Do() {
				t.Fatalf("first reply lost metadata or restored ID: %+v, %v", reply, unpackErr)
			}
			if c.writes.Load() != 1 {
				t.Fatalf("first reply required %d writes, want one", c.writes.Load())
			}
			watch.assertReleased(t, 1)
		})
	}
}

func TestTraditionalDuplicateReplyKeepsFirstAndReleasesBoth(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			watch := newResponseBufferWatch(t)
			c := newEarlyReplyConn(tcp, watch)
			c.replies = 2
			dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: tcp}, c)
			defer dc.Close()
			<-c.beforeRead
			payload, _ := earlyReplyQuery(t)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			r, err := dc.exchange(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			var reply dns.Msg
			unpackErr := reply.Unpack(*r)
			pool.ReleaseBuf(r)
			if unpackErr != nil || reply.Rcode != dns.RcodeRefused {
				t.Fatalf("duplicate replaced the first reply: %v, %v", reply, unpackErr)
			}
			watch.assertReleased(t, 2)
		})
	}
}

func TestResponseQueueDeletionReleasesPendingReply(t *testing.T) {
	watch := newResponseBufferWatch(t)
	r := pool.GetBuf(64)
	watch.record(*r)
	c := make(chan *[]byte, 1)
	c <- r
	dc := &TraditionalDnsConn{queue: map[uint32]chan *[]byte{7: c}}
	dc.deleteQueueC(7)
	if len(dc.queue) != 0 || len(c) != 0 {
		t.Fatal("removed query retained a queued reply")
	}
	watch.assertReleased(t, 1)
}

func TestTraditionalQueuedReplyCanceledClosedOrWriteError(t *testing.T) {
	for _, outcome := range []string{"cancel", "close", "write_error"} {
		t.Run(outcome, func(t *testing.T) {
			for iteration := 0; iteration < 20; iteration++ {
				watch := newResponseBufferWatch(t)
				c := newEarlyReplyConn(false, watch)
				dc := NewDnsConn(TraditionalDnsConnOpts{}, c)
				<-c.beforeRead
				ctx, cancel := context.WithCancelCause(context.Background())
				cause := errors.New(outcome)
				switch outcome {
				case "cancel":
					c.afterDispatch = func() { cancel(cause) }
				case "close":
					c.afterDispatch = func() { dc.CloseWithErr(cause) }
				case "write_error":
					c.writeErr = cause
				}
				payload, _ := earlyReplyQuery(t)
				r, err := dc.exchange(ctx, payload)
				cancel(cause)
				dc.Close()
				if r != nil {
					pool.ReleaseBuf(r)
				}
				// Reply/cancellation/closure can be ready together. Either
				// selection is valid; exactly one owner releases the reply.
				// A failed Write must always return its error.
				if (r == nil) != (err != nil) || (err != nil && !errors.Is(err, cause)) || (outcome == "write_error" && !errors.Is(err, cause)) {
					t.Fatalf("unexpected outcome: response=%v err=%v", r != nil, err)
				}
				watch.assertReleased(t, 1)
			}
		})
	}
}

func TestResponseQueueRemovalRacesReadLoop(t *testing.T) {
	watch := newResponseBufferWatch(t)
	c := newEarlyReplyConn(false, watch)
	dc := NewDnsConn(TraditionalDnsConnOpts{}, c)
	defer dc.Close()
	<-c.beforeRead
	payload, _ := earlyReplyQuery(t)
	for iteration := 0; iteration < 200; iteration++ {
		qid, _ := dc.addQueueC()
		response := append([]byte(nil), payload...)
		binary.BigEndian.PutUint16(response, qid)
		removed := make(chan struct{})
		go func() {
			dc.deleteQueueC(qid)
			close(removed)
		}()
		c.incoming <- response
		<-c.beforeRead // Previous packet has completed dispatch/release.
		<-removed
		watch.assertReleased(t, iteration+1)
	}
}

type earlyReplyConn struct {
	tcp           bool
	watch         *responseBufferWatch
	incoming      chan []byte
	beforeRead    chan struct{}
	closed        chan struct{}
	pending       []byte // One Read owner, including TCP's header/body reads.
	once          sync.Once
	writes        atomic.Int32
	replies       int
	writeErr      error
	afterDispatch func()
}

func newEarlyReplyConn(tcp bool, watch *responseBufferWatch) *earlyReplyConn {
	return &earlyReplyConn{tcp: tcp, watch: watch, incoming: make(chan []byte, 1), beforeRead: make(chan struct{}, 8), closed: make(chan struct{}), replies: 1}
}

func (c *earlyReplyConn) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		c.beforeRead <- struct{}{}
		select {
		case payload := <-c.incoming:
			c.pending = payload
		case <-c.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, c.pending)
	if !c.tcp || len(p) > 2 {
		c.watch.record(p)
	}
	if c.tcp {
		c.pending = c.pending[n:]
	} else {
		c.pending = nil
	}
	return n, nil
}

func (c *earlyReplyConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	offset := 0
	if c.tcp {
		offset = 2
	}
	for i := 0; i < c.replies; i++ {
		response := append([]byte(nil), p...)
		response[offset+2] |= 0x80
		response[offset+3] &= 0xf0
		if i == 0 {
			response[offset+3] |= dns.RcodeRefused
		}
		select {
		case c.incoming <- response:
		case <-c.closed:
			return 0, io.EOF
		}
		<-c.beforeRead // readLoop dispatched the full reply before Write returns.
	}
	if c.afterDispatch != nil {
		c.afterDispatch()
	}
	return len(p), c.writeErr
}

func (c *earlyReplyConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *earlyReplyConn) SetDeadline(time.Time) error      { return nil }
func (c *earlyReplyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *earlyReplyConn) SetWriteDeadline(time.Time) error { return nil }
