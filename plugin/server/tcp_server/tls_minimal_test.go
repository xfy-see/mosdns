//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package tcp_server

import "testing"

func TestMinimalListenerRejectsTLSConfiguration(t *testing.T) {
	for _, args := range []*Args{{Cert: "cert.pem"}, {Key: "key.pem"}, {Cert: "cert.pem", Key: "key.pem"}} {
		wrap, enabled, err := listenerTLS(args)
		if wrap != nil || enabled || err == nil {
			t.Fatalf("TLS listener options silently accepted: %+v, %v", args, err)
		}
	}
	wrap, enabled, err := listenerTLS(&Args{})
	if wrap != nil || enabled || err != nil {
		t.Fatalf("plaintext listener: enabled=%v, err=%v", enabled, err)
	}
}
