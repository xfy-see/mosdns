package pool

import (
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func packingMessages() map[string]*dns.Msg {
	question := new(dns.Msg)
	question.SetQuestion("www.example.test.", dns.TypeA)
	question.Id = 0x1423
	m := new(dns.Msg)
	m.SetReply(question)
	m.Compress = true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, A: net.IPv4(192, 0, 2, 1)}}
	m.SetEdns0(1232, true)
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{0, 1, 2, 3}}}

	large := m.Copy()
	for i := 0; i < 32; i++ {
		large.Answer = append(large.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "txt.example.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600}, Txt: []string{strings.Repeat("x", 250)}})
	}
	compressed := m.Copy()
	for i := 0; i < 128; i++ {
		compressed.Answer = append(compressed.Answer, dns.Copy(m.Answer[0]))
	}
	return map[string]*dns.Msg{"small_A_EDNS": m, "large_TXT": large, "compressed_RRs": compressed}
}

func TestPackBuffersRoundTripAndOwnership(t *testing.T) {
	for name, m := range packingMessages() {
		t.Run(name, func(t *testing.T) {
			want, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			for _, tcp := range []bool{false, true} {
				pack := PackBuffer
				if tcp {
					pack = PackTCPBuffer
				}
				first, err := pack(m)
				if err != nil {
					t.Fatal(err)
				}
				defer ReleaseBuf(first)
				second, err := pack(m)
				if err != nil {
					t.Fatal(err)
				}
				for i := range *second {
					(*second)[i] = 0
				}
				ReleaseBuf(second)
				wire := *first
				if tcp {
					if got := binary.BigEndian.Uint16(wire); int(got) != len(wire)-2 {
						t.Fatalf("bad TCP length: %d vs %d", got, len(wire)-2)
					}
					wire = wire[2:]
				}
				if !reflect.DeepEqual(wire, want) {
					t.Fatal("wire differs from dns.Msg.Pack or was overwritten by another borrow")
				}
				var decoded dns.Msg
				if err := decoded.Unpack(wire); err != nil {
					t.Fatal(err)
				}
				if decoded.Id != m.Id || decoded.IsEdns0() == nil || !decoded.IsEdns0().Do() || len(decoded.Answer) != len(m.Answer) {
					t.Fatal("response metadata changed")
				}
			}
		})
	}
}

func TestPackBuffersErrors(t *testing.T) {
	m := new(dns.Msg)
	m.Rcode = -1
	for _, pack := range []func(*dns.Msg) (*[]byte, error){PackBuffer, PackTCPBuffer} {
		if b, err := pack(m); err == nil || b != nil {
			t.Fatalf("expected nil buffer and pack error, got %v, %v", b, err)
		}
	}
}

func BenchmarkPackBuffer(b *testing.B) {
	for name, m := range packingMessages() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				buf, err := PackBuffer(m)
				if err != nil {
					b.Fatal(err)
				}
				ReleaseBuf(buf)
			}
		})
	}
}

func BenchmarkPackTCPBuffer(b *testing.B) {
	for name, m := range packingMessages() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				buf, err := PackTCPBuffer(m)
				if err != nil {
					b.Fatal(err)
				}
				ReleaseBuf(buf)
			}
		})
	}
}
