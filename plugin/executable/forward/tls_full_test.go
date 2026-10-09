//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import "testing"

func TestProfileTLSConfigOnlyForEncryptedUpstreams(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:53", "udp://127.0.0.1:53", "tcp://127.0.0.1:53", "tcp+pipeline://127.0.0.1:53"} {
		cfg, err := profileTLSConfig(UpstreamConfig{Addr: addr})
		if cfg != nil || err != nil {
			t.Fatalf("plaintext upstream %s allocated TLS config: %v, %v", addr, cfg, err)
		}
	}
	for _, scheme := range []string{"tls", "tls+pipeline", "https", "h3", "quic", "doq", "HTTPS", "TLS+PIPELINE", "H3"} {
		cfg, err := profileTLSConfig(UpstreamConfig{Addr: scheme + "://127.0.0.1", InsecureSkipVerify: true})
		if err != nil || cfg == nil || !cfg.InsecureSkipVerify || cfg.ClientSessionCache == nil {
			t.Fatalf("encrypted upstream %s lost TLS options/cache: %+v, %v", scheme, cfg, err)
		}
	}
}
