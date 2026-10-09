//go:build !mosdns_minimal

// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

package cache

import (
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func interopQuery(name string, typ uint16, flags bool) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.Id = 123
	q.AuthenticatedData = flags
	q.CheckingDisabled = flags
	if flags {
		q.SetEdns0(1232, true)
	}
	return q
}

// Run explicitly with MOSDNS_EXPORT_GO_DUMP to regenerate the Go fixture using
// the actual legacy cache writer; normal test runs never update fixtures.
func TestExportGoCacheDumpInteropFixture(t *testing.T) {
	path := os.Getenv("MOSDNS_EXPORT_GO_DUMP")
	if path == "" {
		t.Skip("fixture generation is explicit")
	}
	c := NewCache(&Args{Size: 32}, Opts{})
	defer c.Close()
	for _, q := range []*dns.Msg{
		interopQuery("dump-a.test.", dns.TypeA, true),
		interopQuery("dump-aaaa.test.", dns.TypeAAAA, false),
		interopQuery("dump-negative.test.", dns.TypeA, false),
	} {
		r := new(dns.Msg)
		r.SetReply(q)
		switch q.Question[0].Name {
		case "dump-a.test.":
			rr, _ := dns.NewRR("dump-a.test. 300 IN A 1.0.1.9")
			r.Answer = []dns.RR{rr}
		case "dump-aaaa.test.":
			rr, _ := dns.NewRR("dump-aaaa.test. 300 IN AAAA 2400:3200::9")
			r.Answer = []dns.RR{rr}
		default:
			r.Rcode = dns.RcodeNameError
		}
		deadline := time.Unix(4102444800, 0) // 2100-01-01 keeps checked-in fixtures usable.
		c.backend.Store(key(getMsgKey(q)), &item{resp: r, storedTime: time.Now(), expirationTime: deadline}, deadline)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	count, err := c.writeDump(f)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil || count != 3 {
		t.Fatalf("exported %d entries: %v", count, err)
	}
}

func TestSharedGoAndRustCacheDumpFixtures(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(source), "../../../tests/fixtures")
	for _, file := range []string{"cache_go_v2.gz", "cache_rust_v2.gz"} {
		t.Run(file, func(t *testing.T) {
			f, err := os.Open(filepath.Join(fixtureDir, file))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			gr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			if gr.Name != dumpHeader {
				t.Fatalf("gzip filename = %q", gr.Name)
			}
			stored := make(map[string]int64)
			for {
				var header [8]byte
				if _, err := io.ReadFull(gr, header[:]); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				length := binary.BigEndian.Uint64(header[:])
				if length > dumpMaximumBlockLength {
					t.Fatal("invalid fixture block length")
				}
				data := make([]byte, length)
				if _, err := io.ReadFull(gr, data); err != nil {
					t.Fatal(err)
				}
				var block CacheDumpBlock
				if err := proto.Unmarshal(data, &block); err != nil {
					t.Fatal(err)
				}
				for _, entry := range block.Entries {
					stored[string(entry.Key)] = entry.MsgStoredTime
				}
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			c := NewCache(&Args{Size: 32}, Opts{})
			defer c.Close()
			if count, err := c.readDump(f); err != nil || count != 3 {
				t.Fatalf("imported %d entries: %v", count, err)
			}
			for _, q := range []*dns.Msg{
				interopQuery("dump-a.test.", dns.TypeA, true),
				interopQuery("dump-aaaa.test.", dns.TypeAAAA, false),
				interopQuery("dump-negative.test.", dns.TypeA, false),
			} {
				msgKey := getMsgKey(q)
				r, lazy := getRespFromCache(msgKey, c.backend, false, 5)
				if r == nil || lazy {
					t.Fatalf("%s: cache miss or lazy hit", q.Question[0].Name)
				}
				if q.Question[0].Name == "dump-negative.test." {
					if r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 {
						t.Fatalf("unexpected negative response %v", r)
					}
					continue
				}
				if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != q.Question[0].Qtype {
					t.Fatalf("unexpected cached answer %v", r)
				}
				want := uint32(1)
				age := time.Now().Unix() - stored[msgKey]
				if age >= 0 && age < 300 {
					want = 300 - uint32(age)
				}
				if got := r.Answer[0].Header().Ttl; got != want {
					t.Errorf("TTL = %d, want %d", got, want)
				}
				if file == "cache_go_v2.gz" && stored[msgKey] != 0 {
					t.Fatal("Go fixture must characterize omitted msg_stored_time")
				}
				if file == "cache_rust_v2.gz" && stored[msgKey] == 0 {
					t.Fatal("Rust writer must preserve stored timestamp for Go readers")
				}
			}
		})
	}
}
