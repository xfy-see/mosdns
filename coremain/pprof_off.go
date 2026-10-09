//go:build !pprof && !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package coremain

import "github.com/go-chi/chi/v5"

func registerPprof(chi.Router) {}
