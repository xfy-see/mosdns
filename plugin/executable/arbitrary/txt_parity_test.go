// SPDX-License-Identifier: GPL-3.0-or-later
package arbitrary

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// Compare encoded RDATA, not TXT.String(), which intentionally escapes binary
// octets and can conceal differences in their underlying representation.
func TestSharedTXTWireFixture(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/arbitrary_txt.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FormatVersion int `json:"format_version"`
		Cases         []struct {
			Name    string     `json:"name"`
			Zone    string     `json:"zone"`
			QName   string     `json:"qname"`
			TTL     uint32     `json:"ttl"`
			Answers [][]string `json:"answers"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 {
		t.Fatalf("unexpected version %d", fixture.FormatVersion)
	}
	for index, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			plugin, err := NewArbitrary(&Args{Rules: []string{item.Zone}})
			if err != nil {
				t.Fatal(err)
			}
			query := new(dns.Msg)
			query.SetQuestion(item.QName, dns.TypeTXT)
			query.Id = uint16(index + 100)
			ctx := query_context.NewContext(query)
			if err := plugin.Exec(context.Background(), ctx); err != nil {
				t.Fatal(err)
			}
			response := ctx.R()
			if response == nil || response.Rcode != dns.RcodeSuccess || response.Id != query.Id {
				t.Fatalf("unexpected response: %+v", response)
			}
			wire, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(dns.Msg)
			if err := decoded.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Answer) != len(item.Answers) {
				t.Fatalf("answers: got %d want %d", len(decoded.Answer), len(item.Answers))
			}
			for i, rr := range decoded.Answer {
				if rr.Header().Ttl != item.TTL {
					t.Fatalf("TTL: got %d want %d", rr.Header().Ttl, item.TTL)
				}
				buf := make([]byte, 65535)
				end, err := dns.PackRR(rr, buf, 0, nil, false)
				if err != nil {
					t.Fatal(err)
				}
				_, offset, err := dns.UnpackDomainName(buf, 0)
				if err != nil {
					t.Fatal(err)
				}
				data := buf[offset+10 : end]
				for segment, wantHex := range item.Answers[i] {
					want, err := hex.DecodeString(wantHex)
					if err != nil {
						t.Fatal(err)
					}
					if len(data) == 0 || len(data) < int(data[0])+1 {
						t.Fatalf("missing or truncated segment %d: %x", segment, data)
					}
					length := int(data[0])
					got := data[1 : length+1]
					if !bytes.Equal(got, want) {
						t.Fatalf("answer %d segment %d: got %x want %x", i, segment, got, want)
					}
					data = data[length+1:]
				}
				if len(data) != 0 {
					t.Fatalf("unconsumed RDATA: %x", data)
				}
			}
		})
	}
}
