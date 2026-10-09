//go:build !mosdns_minimal

package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func BenchmarkReadMsgFromReqGet(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeAAAA)
	m.SetEdns0(1232, true)
	wire, err := m.Pack()
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire), nil)
	req.Header.Set("Accept", "application/dns-message")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ReadMsgFromReq(req); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReadMsgFromReqRejectsOversizePost(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	body := append(wire, make([]byte, dns.MaxMsgSize+1-len(wire))...)
	for _, declaredLength := range []int64{int64(len(body)), -1} {
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		req.ContentLength = declaredLength
		req.Header.Set("Content-Type", "application/dns-message")
		if _, err := ReadMsgFromReq(req); err == nil {
			t.Fatalf("accepted an oversized POST body with declared length %d", declaredLength)
		}
	}
}

func TestReadMsgFromReqPreservesEDNS(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeAAAA)
	m.Id = 237
	m.SetEdns0(4096, true)
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3, 4}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire)),
		httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire), nil),
	}
	requests[0].Header.Set("Content-Type", "application/dns-message")
	requests[1].Header.Set("Accept", "application/dns-message")
	for _, req := range requests {
		got, err := ReadMsgFromReq(req)
		if err != nil {
			t.Fatal(err)
		}
		opt := got.IsEdns0()
		if got.Id != m.Id || got.Question[0] != m.Question[0] || opt == nil || opt.UDPSize() != 4096 || !opt.Do() || len(opt.Option) != 1 {
			t.Fatal("request metadata changed")
		}
		// Reuse the decoder pools and verify the decoded message owns its
		// question/EDNS data after ReadMsgFromReq returns.
		for i := 0; i < 10; i++ {
			if _, err := ReadMsgFromReq(requests[1]); err != nil {
				t.Fatal(err)
			}
		}
		if local := opt.Option[0].(*dns.EDNS0_LOCAL); !reflect.DeepEqual(local.Data, []byte{1, 2, 3, 4}) {
			t.Fatal("EDNS option data was overwritten by decoder buffer reuse")
		}
	}
}

func TestReadMsgFromReqPostMaximum(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeA)
	m.SetEdns0(65535, false)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: make([]byte, dns.MaxMsgSize-len(wire)-4)}}
	wire, err = m.Pack()
	if err != nil || len(wire) != dns.MaxMsgSize {
		t.Fatalf("invalid maximum length fixture: len=%d, err=%v", len(wire), err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")
	if _, err := ReadMsgFromReq(req); err != nil {
		t.Fatalf("rejected a valid maximum length request: %v", err)
	}
}

func TestReadMsgFromReqGetDecodeErrors(t *testing.T) {
	for _, query := range []string{"_", "!!!", "aGVsbG8"} {
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+query, nil)
		req.Header.Set("Accept", "application/dns-message")
		if _, err := ReadMsgFromReq(req); err == nil {
			t.Fatalf("accepted invalid DNS query %q", query)
		}
	}
}
