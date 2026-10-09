// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import "testing"

func BenchmarkPlainForwardInit(b *testing.B) {
	args := &Args{Upstreams: []UpstreamConfig{{Addr: "192.0.2.1:53"}, {Addr: "198.51.100.1:53"}}}
	b.ReportAllocs()
	for b.Loop() {
		f, err := NewForward(args, Opts{})
		if err != nil {
			b.Fatal(err)
		}
		if err := f.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
