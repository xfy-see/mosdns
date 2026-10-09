//go:build !mosdns_minimal

package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"
)

func TestDumpRejectsLegacyCollidingQuestionType(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("legacy.example.", dns.TypeA)
	legacyKey := []byte(getMsgKey(q))
	response := new(dns.Msg)
	response.SetReply(q)
	response.Question[0].Qtype = dns.TypeCAA
	rr, err := dns.NewRR("legacy.example. 300 IN CAA 0 issue ca.example")
	if err != nil {
		t.Fatal(err)
	}
	response.Answer = []dns.RR{rr}
	msg, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).Unix()
	block, err := proto.Marshal(&CacheDumpBlock{Entries: []*CachedEntry{{Key: legacyKey, Msg: msg, CacheExpirationTime: future, MsgExpirationTime: future}}})
	if err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	w, err := gzip.NewWriterLevel(&dump, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	w.Name = dumpHeader
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(len(block)))
	if _, err := w.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(block); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	if _, err := c.readDump(&dump); err != nil {
		t.Fatal(err)
	}
	if got, _ := getRespFromCache(string(legacyKey), c.backend, false, 5); got != nil {
		t.Fatal("legacy CAA entry loaded under an A query's key")
	}
}

func TestDumpPreservesStoredTimeAndFreshTTL(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("stored.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	rr, err := dns.NewRR("stored.example. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{rr}
	source := NewCache(&Args{}, Opts{})
	defer source.Close()
	msgKey := getMsgKey(q)
	if !saveRespToCache(msgKey, r, source.backend, 0) {
		t.Fatal("failed to store response")
	}
	var dump bytes.Buffer
	if _, err := source.writeDump(&dump); err != nil {
		t.Fatal(err)
	}
	destination := NewCache(&Args{}, Opts{})
	defer destination.Close()
	if _, err := destination.readDump(&dump); err != nil {
		t.Fatal(err)
	}
	cached, lazy := getRespFromCache(msgKey, destination.backend, false, 5)
	if cached == nil || lazy || len(cached.Answer) != 1 {
		t.Fatal("fresh dumped response did not load")
	}
	if ttl := cached.Answer[0].Header().Ttl; ttl < 298 || ttl > 300 {
		t.Fatalf("fresh dumped response TTL = %d, want approximately 300", ttl)
	}
}
