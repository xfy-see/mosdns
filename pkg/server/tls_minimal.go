//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package server

import "net"

func tcpServerName(_ net.Conn) string { return "" }
