//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package tcp_server

import (
	"fmt"
	"net"
)

func listenerTLS(args *Args) (func(net.Listener) net.Listener, bool, error) {
	if len(args.Key)+len(args.Cert) != 0 {
		return nil, false, fmt.Errorf("tcp_server cert/key require the full profile; mosdns_minimal supports plaintext UDP/TCP DNS")
	}
	return nil, false, nil
}
