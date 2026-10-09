// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

func registerProcessMetrics(r Registerer) { registerUnixMetrics(r, "/dev/fd") }
