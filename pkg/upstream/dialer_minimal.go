//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

func profileDialers(scheme, addrUrlHost string, opt Opt, dialer *net.Dialer) (
	func(bool, uint16) (func(context.Context) (net.Conn, error), error),
	func(uint16) (func(context.Context) (*net.UDPAddr, error), error),
	error,
) {
	// UDP uses its own numeric-address dialer and TCP fallback. Do not retain
	// the unrelated TCP/bootstrap closures in each plaintext upstream.
	if scheme == "udp" || scheme == "" {
		return nil, nil, nil
	}

	tcp := func(_ bool, defaultPort uint16) (func(context.Context) (net.Conn, error), error) {
		host, port, err := parseDialAddr(addrUrlHost, opt.DialAddr, defaultPort)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("addr must be an ip address, %w", err)
		}
		dialAddr := joinPort(host, port)
		return func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddr)
		}, nil
	}
	return tcp, nil, nil
}
