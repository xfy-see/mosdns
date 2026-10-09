// SPDX-License-Identifier: GPL-3.0-or-later
package arbitrary

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

type zoneWireRecord struct {
	Owner     string `json:"owner"`
	OwnerWire string `json:"owner_wire"`
	Type      uint16 `json:"type"`
	Class     uint16 `json:"class"`
	TTL       uint32 `json:"ttl"`
	RData     string `json:"rdata"`
}
type zoneWireCase struct {
	Name    string           `json:"name"`
	Group   string           `json:"group"`
	Zone    string           `json:"zone"`
	Error   bool             `json:"error"`
	Records []zoneWireRecord `json:"records"`
}
type zoneWireFixture struct {
	FormatVersion int            `json:"format_version"`
	Source        string         `json:"source"`
	Cases         []zoneWireCase `json:"cases"`
}

func zoneWire(rr dns.RR) (zoneWireRecord, error) {
	buffer := make([]byte, 65535)
	end, err := dns.PackRR(rr, buffer, 0, nil, false)
	if err != nil {
		return zoneWireRecord{}, err
	}
	_, offset, err := dns.UnpackDomainName(buffer, 0)
	if err != nil {
		return zoneWireRecord{}, err
	}
	return zoneWireRecord{
		Owner:     rr.Header().Name,
		OwnerWire: hex.EncodeToString(buffer[:offset]),
		Type:      rr.Header().Rrtype, Class: rr.Header().Class, TTL: rr.Header().Ttl,
		RData: hex.EncodeToString(buffer[offset+10 : end]),
	}, nil
}

// This diagnostic preserves a proven miekg/dns v1.1.72 behavior, not a desired
// AMTRELAY encoding. scan_rr.go masks the discovery bit while parsing, but
// zmsg.go passes the unmasked value to packIPSECGateway, which omits the host.
func TestAMTRelayDiscoveryGatewayDiagnostic(t *testing.T) {
	rr, err := dns.NewRR("rr.Example. 73 IN AMTRELAY 10 1 3 gateway.Example.")
	if err != nil {
		t.Fatal(err)
	}
	record, err := zoneWire(rr)
	if err != nil {
		t.Fatal(err)
	}
	if record.RData != "0a83" {
		t.Fatalf("Go known discovery-bit encoding changed: %s", record.RData)
	}
}

// MOSDNS_UPDATE_ZONE_FIXTURE=1 is an explicit development-only fixture refresh.
// Default tests never write files; expected octets are checked in for Rust too.
func TestSharedZoneWireFixture(t *testing.T) {
	const path = "../../../tests/fixtures/zone_records.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture zoneWireFixture
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FormatVersion != 1 {
		t.Fatalf("unexpected version %d", fixture.FormatVersion)
	}
	update := os.Getenv("MOSDNS_UPDATE_ZONE_FIXTURE") == "1"
	for index := range fixture.Cases {
		item := &fixture.Cases[index]
		t.Run(item.Name, func(t *testing.T) {
			parser := dns.NewZoneParser(strings.NewReader(item.Zone), "", "")
			parser.SetDefaultTTL(3600)
			var records []dns.RR
			for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
				records = append(records, rr)
			}
			if item.Error {
				if parser.Err() == nil {
					t.Fatal("expected Go parser rejection")
				}
				return
			}
			if parser.Err() != nil {
				t.Fatal(parser.Err())
			}
			got := make([]zoneWireRecord, 0, len(records))
			for _, rr := range records {
				wire, err := zoneWire(rr)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, wire)
			}
			if update {
				item.Records = got
			} else if !reflect.DeepEqual(got, item.Records) {
				t.Fatalf("Go uncompressed wire changed:\ngot %+v\nwant %+v", got, item.Records)
			}
			plugin, err := NewArbitrary(&Args{Rules: []string{item.Zone}})
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				query := new(dns.Msg)
				query.SetQuestion(record.Header().Name, record.Header().Rrtype)
				query.Question[0].Qclass = record.Header().Class
				ctx := query_context.NewContext(query)
				if err := plugin.Exec(context.Background(), ctx); err != nil {
					t.Fatal(err)
				}
				response := ctx.R()
				if response == nil {
					t.Fatal("missing arbitrary response")
				}
				var want []dns.RR
				for _, rr := range records {
					if strings.EqualFold(rr.Header().Name, record.Header().Name) &&
						rr.Header().Rrtype == record.Header().Rrtype &&
						rr.Header().Class == record.Header().Class {
						want = append(want, rr)
					}
				}
				if len(response.Answer) != len(want) {
					t.Fatal("answer count/order changed")
				}
				for i, rr := range response.Answer {
					gotWire, err := zoneWire(rr)
					if err != nil {
						t.Fatal(err)
					}
					wantWire, err := zoneWire(want[i])
					if err != nil {
						t.Fatal(err)
					}
					gotBytes, _ := json.Marshal(gotWire)
					wantBytes, _ := json.Marshal(wantWire)
					if !bytes.Equal(gotBytes, wantBytes) {
						t.Fatalf("answer %d wire differs", i)
					}
				}
			}
		})
	}
	if update && !t.Failed() {
		data, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
