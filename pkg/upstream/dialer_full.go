//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"context"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/bootstrap"
	"golang.org/x/net/proxy"
	"net"
	"net/netip"
	"strconv"
)

func profileDialers(scheme, addrUrlHost string, opt Opt, dialer *net.Dialer) (
	func(bool, uint16) (func(context.Context) (net.Conn, error), error),
	func(uint16) (func(context.Context) (*net.UDPAddr, error), error),
	error,
) {
	var err error
	var bootstrapAp netip.AddrPort
	if s := opt.Bootstrap; len(s) > 0 {
		bootstrapAp, err = parseBootstrapAp(s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bootstrap, %w", err)
		}
	}

	// UDP uses its own numeric-address dialer and TCP fallback. Do not retain
	// the unrelated TCP/bootstrap closures in each plaintext upstream.
	if scheme == "udp" || scheme == "" {
		return nil, nil, nil
	}

	newUdpAddrResolveFunc := func(defaultPort uint16) (func(ctx context.Context) (*net.UDPAddr, error), error) {
		host, port, err := parseDialAddr(addrUrlHost, opt.DialAddr, defaultPort)
		if err != nil {
			return nil, err
		}

		if addr, err := netip.ParseAddr(host); err == nil { // host is an ip.
			ua := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port))
			return func(ctx context.Context) (*net.UDPAddr, error) {
				return ua, nil
			}, nil
		} else { // Not an ip, assuming it's a domain name.
			if bootstrapAp.IsValid() {
				// Bootstrap enabled.
				bs, err := bootstrap.New(host, port, bootstrapAp, opt.BootstrapVer, opt.Logger)
				if err != nil {
					return nil, err
				}

				return func(ctx context.Context) (*net.UDPAddr, error) {
					s, err := bs.GetAddrPortStr(ctx)
					if err != nil {
						return nil, fmt.Errorf("bootstrap failed, %w", err)
					}
					return net.ResolveUDPAddr("udp", s)
				}, nil
			} else {
				// Bootstrap disabled.
				dialAddr := joinPort(host, port)
				return func(ctx context.Context) (*net.UDPAddr, error) {
					return net.ResolveUDPAddr("udp", dialAddr)
				}, nil
			}
		}
	}

	newTcpDialer := func(dialAddrMustBeIp bool, defaultPort uint16) (func(ctx context.Context) (net.Conn, error), error) {
		host, port, err := parseDialAddr(addrUrlHost, opt.DialAddr, defaultPort)
		if err != nil {
			return nil, err
		}

		// Socks5 enabled.
		if s5Addr := opt.Socks5; len(s5Addr) > 0 {
			socks5Dialer, err := proxy.SOCKS5("tcp", s5Addr, nil, dialer)
			if err != nil {
				return nil, fmt.Errorf("failed to init socks5 dialer: %w", err)
			}

			contextDialer := socks5Dialer.(proxy.ContextDialer)
			dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			return func(ctx context.Context) (net.Conn, error) {
				return contextDialer.DialContext(ctx, "tcp", dialAddr)
			}, nil
		}

		if _, err := netip.ParseAddr(host); err == nil {
			// Host is an ip addr. No need to resolve it.
			dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			return func(ctx context.Context) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", dialAddr)
			}, nil
		} else {
			if dialAddrMustBeIp {
				return nil, errors.New("addr must be an ip address")
			}
			// Host is not an ip addr, assuming it is a domain.
			if bootstrapAp.IsValid() {
				// Bootstrap enabled.
				bs, err := bootstrap.New(host, port, bootstrapAp, opt.BootstrapVer, opt.Logger)
				if err != nil {
					return nil, err
				}

				return func(ctx context.Context) (net.Conn, error) {
					dialAddr, err := bs.GetAddrPortStr(ctx)
					if err != nil {
						return nil, fmt.Errorf("bootstrap failed, %w", err)
					}
					return dialer.DialContext(ctx, "tcp", dialAddr)
				}, nil
			} else {
				// Bootstrap disabled.
				dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
				return func(ctx context.Context) (net.Conn, error) {
					return dialer.DialContext(ctx, "tcp", dialAddr)
				}, nil
			}
		}
	}
	return newTcpDialer, newUdpAddrResolveFunc, nil
}
