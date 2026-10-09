//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import (
	"crypto/tls"
	"strings"
)

// Plain UDP/TCP upstreams do not need an unused TLS session cache.
func profileTLSConfig(c UpstreamConfig) (*tls.Config, error) {
	scheme, _, found := strings.Cut(c.Addr, "://")
	scheme = strings.ToLower(scheme)
	if !found || (scheme != "tls" && scheme != "tls+pipeline" && scheme != "https" && scheme != "h3" && scheme != "quic" && scheme != "doq") {
		return nil, nil
	}
	return &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}, nil
}
