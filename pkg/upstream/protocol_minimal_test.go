//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package upstream

import (
	"strings"
	"testing"
)

func TestMinimalProfileRejectsUnavailableTransports(t *testing.T) {
	for _, scheme := range []string{"tls", "tls+pipeline", "https", "h3", "quic", "doq", "ftp"} {
		t.Run(scheme, func(t *testing.T) {
			u, err := NewUpstream(scheme+"://127.0.0.1", Opt{})
			if u != nil || err == nil || !strings.Contains(err.Error(), "mosdns_minimal") {
				t.Fatalf("unsupported transport %s: upstream=%v error=%v", scheme, u, err)
			}
		})
	}
	for _, opt := range []Opt{{EnableHTTP3: true}, {Socks5: "127.0.0.1:1080"}, {Bootstrap: "127.0.0.1"}, {BootstrapVer: 6}} {
		if u, err := NewUpstream("127.0.0.1:53", opt); u != nil || err == nil {
			t.Fatalf("unsupported options were silently accepted: %+v, upstream=%v error=%v", opt, u, err)
		}
	}
	for _, scheme := range []string{"udp", "tcp", "tcp+pipeline"} {
		u, err := NewUpstream(scheme+"://127.0.0.1:53", Opt{})
		if err != nil {
			t.Fatalf("required transport %s: %v", scheme, err)
		}
		_ = u.Close()
	}
}
