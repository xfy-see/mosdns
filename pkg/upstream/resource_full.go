//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/doh"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/transport"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// quic.Transport does not close a PacketConn supplied by its caller. This
// resolver creates that socket, so it must release both resources explicitly.
type ownedQUICSocket struct {
	transport *quic.Transport
	conn      net.PacketConn
	once      sync.Once
	closeErr  error
}

func (c *ownedQUICSocket) Close() error {
	c.once.Do(func() { c.closeErr = errors.Join(c.transport.Close(), c.conn.Close()) })
	return c.closeErr
}

// Close protocol connections before their shared QUIC transport and UDP socket.
type upstreamWithOwnedCloser struct {
	Upstream
	closer   io.Closer
	once     sync.Once
	closeErr error
}

func (u *upstreamWithOwnedCloser) Close() error {
	u.once.Do(func() { u.closeErr = errors.Join(u.Upstream.Close(), u.closer.Close()) })
	return u.closeErr
}

func newDoHWithOwnedTransport(addr string, rt http.RoundTripper, owned io.Closer, logger *zap.Logger) (Upstream, error) {
	u, err := doh.NewUpstream(addr, rt, logger)
	if err != nil {
		// A failed constructor must discard resources already acquired by its caller.
		if c, ok := rt.(io.Closer); ok {
			_ = c.Close()
		} else if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
		if owned != nil {
			_ = owned.Close()
		}
		return nil, fmt.Errorf("failed to create doh upstream, %w", err)
	}
	if owned == nil {
		return u, nil
	}
	return &upstreamWithOwnedCloser{Upstream: u, closer: owned}, nil
}

// net/http may finish a canceled RoundTrip before its HTTP/2 stream cleanup.
// Retain ownership of the raw sockets so Close cannot leave such a connection
// in the pool. Remove normally closed sockets to avoid retaining old connections.
type ownedHTTPConns struct {
	mu       sync.Mutex
	closed   bool
	conns    map[*ownedHTTPConn]struct{}
	once     sync.Once
	closeErr error
}

type ownedHTTPConn struct {
	net.Conn
	owner    *ownedHTTPConns
	once     sync.Once
	closeErr error
}

func (o *ownedHTTPConns) wrap(c net.Conn) (net.Conn, error) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		_ = c.Close()
		return nil, transport.ErrClosedTransport
	}
	wrapped := &ownedHTTPConn{Conn: c, owner: o}
	if o.conns == nil {
		o.conns = make(map[*ownedHTTPConn]struct{})
	}
	o.conns[wrapped] = struct{}{}
	o.mu.Unlock()
	return wrapped, nil
}

func (c *ownedHTTPConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.closeErr
}

func (o *ownedHTTPConns) Close() error {
	o.once.Do(func() {
		o.mu.Lock()
		o.closed = true
		conns := make([]*ownedHTTPConn, 0, len(o.conns))
		for c := range o.conns {
			conns = append(conns, c)
		}
		o.conns = nil
		o.mu.Unlock()
		errs := make([]error, 0, len(conns))
		for _, c := range conns {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		o.closeErr = errors.Join(errs...)
	})
	return o.closeErr
}
