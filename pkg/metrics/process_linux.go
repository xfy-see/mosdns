// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type processSnapshot struct {
	mu     sync.Mutex
	at     time.Time
	values map[string]float64
}

func (p *processSnapshot) read(name string) (float64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.at) >= 100*time.Millisecond {
		p.values = readLinuxProcess()
		p.at = time.Now()
	}
	v, ok := p.values[name]
	return v, ok
}
func readLinuxProcess() map[string]float64 {
	values := map[string]float64{}
	// status supplies byte counts without depending on the kernel's clock tick rate.
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				continue
			}
			switch fields[0] {
			case "VmSize:":
				values["process_virtual_memory_bytes"] = v * 1024
			case "VmRSS:":
				values["process_resident_memory_bytes"] = v * 1024
			}
		}
	}
	// Linux exposes the process's monotonic start time in /proc/self/sched;
	// se.exec_start is not the process birth time, so use stat's starttime plus
	// the kernel AT_CLKTCK tick rate and btime instead.
	if data, err := os.ReadFile("/proc/self/stat"); err == nil {
		close := strings.LastIndexByte(string(data), ')')
		if close >= 0 {
			fields := strings.Fields(string(data)[close+1:])
			if len(fields) > 19 {
				start, err := strconv.ParseFloat(fields[19], 64)
				ticks, ok := linuxClockTicks()
				if err == nil && ok {
					if data, err := os.ReadFile("/proc/stat"); err == nil {
						for _, line := range strings.Split(string(data), "\n") {
							fields := strings.Fields(line)
							if len(fields) == 2 && fields[0] == "btime" {
								seconds, err := strconv.ParseFloat(fields[1], 64)
								if err == nil {
									values["process_start_time_seconds"] = seconds + start/ticks
								}
								break
							}
						}
					}
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/self/net/dev"); err == nil {
		var received, transmitted float64
		valid := false
		for _, line := range strings.Split(string(data), "\n") {
			colon := strings.IndexByte(line, ':')
			if colon < 0 {
				continue
			}
			fields := strings.Fields(line[colon+1:])
			if len(fields) < 9 {
				continue
			}
			rx, e1 := strconv.ParseFloat(fields[0], 64)
			tx, e2 := strconv.ParseFloat(fields[8], 64)
			if e1 == nil && e2 == nil {
				received += rx
				transmitted += tx
				valid = true
			}
		}
		if valid {
			values["process_network_receive_bytes_total"] = received
			values["process_network_transmit_bytes_total"] = transmitted
		}
	}
	return values
}
func linuxClockTicks() (float64, bool) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, false
	}
	word := strconv.IntSize / 8
	// Native auxv words use the process architecture's byte order, selected by
	// a separate file so big-endian MIPS uses the same exact AT_CLKTCK source.
	for offset := 0; offset+2*word <= len(data); offset += 2 * word {
		if auxWord(data[offset:offset+word]) == 17 {
			return float64(auxWord(data[offset+word : offset+2*word])), true
		}
	}
	return 0, false
}
func registerProcessMetrics(r Registerer) {
	registerUnixMetrics(r, "/proc/self/fd")
	snapshot := new(processSnapshot)
	for _, field := range []struct {
		name, help string
		kind       MetricType
	}{
		{"process_virtual_memory_bytes", "Virtual memory size in bytes.", GaugeType},
		{"process_resident_memory_bytes", "Resident memory size in bytes.", GaugeType},
		{"process_start_time_seconds", "Start time of the process since unix epoch in seconds.", GaugeType},
		{"process_network_receive_bytes_total", "Number of bytes received by the process over the network.", CounterType},
		{"process_network_transmit_bytes_total", "Number of bytes sent by the process over the network.", CounterType},
	} {
		registerFunction(r, field.name, field.help, field.kind, func() (float64, bool) { return snapshot.read(field.name) })
	}
}
