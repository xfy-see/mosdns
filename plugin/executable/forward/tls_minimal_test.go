//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import "testing"

func TestMinimalTLSConfigBoundary(t *testing.T) {
	cfg, err := profileTLSConfig(UpstreamConfig{Addr: "udp://127.0.0.1:53"})
	if cfg != nil || err != nil {
		t.Fatalf("minimal TLS allocation: %+v, %v", cfg, err)
	}
	cfg, err = profileTLSConfig(UpstreamConfig{InsecureSkipVerify: true})
	if cfg != nil || err == nil {
		t.Fatalf("TLS-only option accepted: %+v, %v", cfg, err)
	}
}
