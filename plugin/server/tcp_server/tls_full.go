//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package tcp_server

import (
	"crypto/tls"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"net"
)

func listenerTLS(args *Args) (func(net.Listener) net.Listener, bool, error) {
	if len(args.Key)+len(args.Cert) == 0 {
		return nil, false, nil
	}
	tc := new(tls.Config)
	if err := server.LoadCert(tc, args.Cert, args.Key); err != nil {
		return nil, false, fmt.Errorf("failed to read tls cert, %w", err)
	}
	return func(l net.Listener) net.Listener { return tls.NewListener(l, tc) }, true, nil
}
