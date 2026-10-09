//go:build !mosdns_minimal && (linux || darwin)

// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// Construction creates UDP sockets without dialing the upstream. Enumerating
// only our process's datagram descriptors makes the failed-construction cleanup
// observable, including sockets which never served a request.
func constructorUDPSockets(t *testing.T) map[string]struct{} {
	t.Helper()
	path := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		path = "/dev/fd"
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Readdirnames avoids lstat on /dev/fd entries that can disappear while
	// the directory is read (including the directory descriptor itself).
	names, err := directory.Readdirnames(-1)
	_ = directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	sockets := make(map[string]struct{})
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || typ != unix.SOCK_DGRAM {
			continue
		}
		addr, err := unix.Getsockname(fd)
		if err != nil {
			continue
		}
		switch addr := addr.(type) {
		case *unix.SockaddrInet4:
			if addr.Port > 0 {
				sockets[fmt.Sprintf("%d/ipv4/%d/%v", fd, addr.Port, addr.Addr)] = struct{}{}
			}
		case *unix.SockaddrInet6:
			if addr.Port > 0 {
				sockets[fmt.Sprintf("%d/ipv6/%d/%v", fd, addr.Port, addr.Addr)] = struct{}{}
			}
		}
	}
	return sockets
}

func TestFailedForwardConstructionClosesEarlierQUICSockets(t *testing.T) {
	// A GC finalizer could conceal a missing explicit Close in an unused socket.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	for _, scheme := range []string{"doq", "h3"} {
		for _, failure := range []string{"empty_addr", "invalid_addr", "duplicate_tag"} {
			t.Run(scheme+"/"+failure, func(t *testing.T) {
				first := UpstreamConfig{Addr: scheme + "://192.0.2.1", Tag: "same"}
				second := UpstreamConfig{Addr: "", Tag: "other"}
				switch failure {
				case "invalid_addr":
					second.Addr = "udp://invalid-host"
				case "duplicate_tag":
					second = UpstreamConfig{Addr: scheme + "://198.51.100.1", Tag: "same"}
				}
				before := constructorUDPSockets(t)
				f, err := NewForward(&Args{Upstreams: []UpstreamConfig{first, second}}, Opts{})
				if f != nil {
					_ = f.Close()
				}
				if err == nil || f != nil {
					t.Fatalf("invalid forward construction returned %v, %v", f, err)
				}
				after := constructorUDPSockets(t)
				for socket := range after {
					if _, existed := before[socket]; !existed {
						t.Errorf("failed construction retained UDP socket %s: %v", socket, err)
					}
				}
			})
		}
	}
}
