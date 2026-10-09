// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"github.com/miekg/dns"
)

type handlerFunc func(context.Context, *dns.Msg, QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte

func (f handlerFunc) Handle(ctx context.Context, m *dns.Msg, meta QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	return f(ctx, m, meta, pack)
}
