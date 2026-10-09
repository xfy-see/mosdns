//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

// The minimal profile covers the CN-site/direct and non-CN-site/tunnel resolver.
// Use the default build for any plugin or encrypted DNS protocol absent here.
package plugin

import (
	_ "github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/executable/nftset"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/matcher/has_resp"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/matcher/qname"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/server/tcp_server"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/server/udp_server"
)
