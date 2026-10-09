// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux || darwin

package metrics

import (
	"os"
	"syscall"
)

func registerUnixMetrics(r Registerer, fdPath string) {
	registerFunction(r, "process_cpu_seconds_total", "Total user and system CPU time spent in seconds.", CounterType, func() (float64, bool) {
		var usage syscall.Rusage
		if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
			return 0, false
		}
		return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6, true
	})
	registerFunction(r, "process_open_fds", "Number of open file descriptors.", GaugeType, func() (float64, bool) {
		f, err := os.Open(fdPath)
		if err != nil {
			return 0, false
		}
		defer f.Close()
		names, err := f.Readdirnames(0)
		if err != nil {
			return 0, false
		}
		return float64(len(names) - 1), true
	})
	for _, field := range []struct {
		name, help string
		limit      int
	}{
		{"process_max_fds", "Maximum number of open file descriptors.", syscall.RLIMIT_NOFILE},
		{"process_virtual_memory_max_bytes", "Maximum amount of virtual memory available in bytes.", syscall.RLIMIT_AS},
	} {
		registerFunction(r, field.name, field.help, GaugeType, func() (float64, bool) {
			var limit syscall.Rlimit
			if syscall.Getrlimit(field.limit, &limit) != nil {
				return 0, false
			}
			return float64(limit.Cur), true
		})
	}
}
