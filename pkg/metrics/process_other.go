// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux && !darwin

package metrics

func registerProcessMetrics(Registerer) {}
