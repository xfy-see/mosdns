// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"net/netip"
	"testing"
)

func TestOriginRestrictsServicePorts(t *testing.T) {
	for _, s := range []string{"example.com:22", "example.com", "example.com:443:80", ":443"} {
		if _, _, err := origin(s); err == nil { t.Fatalf("accepted %q", s) }
	}
	host, port, err := origin("EXAMPLE.com.:443")
	if err != nil || host != "example.com" || port != "443" { t.Fatalf("invalid origin parsing: %q %q %v", host, port, err) }
}

func TestPrivateDestinationsCannotBeProxied(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "192.168.100.1", "169.254.1.1", "::1", "224.0.0.1", "0.0.0.0", "100.64.1.1", "198.18.0.1", "198.51.100.1", "240.0.0.1"} {
		if public(netip.MustParseAddr(s)) { t.Fatalf("accepted private/non-IPv4 destination %s", s) }
	}
	if !public(netip.MustParseAddr("1.1.1.1")) { t.Fatal("rejected public IPv4") }
}
