//go:build pprof && !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package coremain

import (
	"github.com/go-chi/chi/v5"
	"net/http/pprof"
)

// Profiling is opt-in: go build -tags=pprof.
func registerPprof(mux chi.Router) {
	mux.Route("/debug/pprof", func(r chi.Router) {
		r.Get("/*", pprof.Index)
		r.Get("/cmdline", pprof.Cmdline)
		r.Get("/profile", pprof.Profile)
		r.Get("/symbol", pprof.Symbol)
		r.Get("/trace", pprof.Trace)
	})
}
