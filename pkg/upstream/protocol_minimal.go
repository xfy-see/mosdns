//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

func checkProfileOptions(scheme string, opt Opt) error {
	if scheme != "udp" && scheme != "tcp" && scheme != "" {
		return fmt.Errorf("protocol [%s] is unavailable in mosdns_minimal (supports udp/tcp)", scheme)
	}
	if opt.EnableHTTP3 {
		return fmt.Errorf("enable_http3 is unavailable in mosdns_minimal")
	}
	if opt.Socks5 != "" || opt.Bootstrap != "" || opt.BootstrapVer != 0 {
		return fmt.Errorf("socks5/bootstrap options require the full profile; mosdns_minimal uses numeric UDP/TCP upstream addresses")
	}

	return nil
}

func newEncryptedUpstream(addrURL *url.URL, _ Opt,
	_ func(bool, uint16) (func(context.Context) (net.Conn, error), error),
	_ func(uint16) (func(context.Context) (*net.UDPAddr, error), error),
) (Upstream, error) {
	return nil, fmt.Errorf("protocol [%s] is unavailable in mosdns_minimal (supports udp/tcp)", addrURL.Scheme)
}
