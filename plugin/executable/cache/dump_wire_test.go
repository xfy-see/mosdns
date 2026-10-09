//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"bytes"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func legacyDumpBlock(block *dumpBlock) *CacheDumpBlock {
	old := new(CacheDumpBlock)
	for _, e := range block.Entries {
		if e == nil {
			old.Entries = append(old.Entries, nil)
			continue
		}
		old.Entries = append(old.Entries, &CachedEntry{
			Key: e.Key, Msg: e.Msg, CacheExpirationTime: e.CacheExpirationTime,
			MsgExpirationTime: e.MsgExpirationTime, MsgStoredTime: e.MsgStoredTime,
		})
	}
	return old
}

func assertDumpWireCompatibility(t *testing.T, b []byte) {
	t.Helper()
	var old CacheDumpBlock
	oldErr := proto.Unmarshal(b, &old)
	got, err := unmarshalDumpBlock(b)
	if (err == nil) != (oldErr == nil) {
		t.Fatalf("decoder acceptance differs for %x: wire=%v, legacy=%v", b, err, oldErr)
	}
	if err != nil {
		return
	}
	if len(got.Entries) != len(old.Entries) {
		t.Fatalf("entry count differs: %d != %d", len(got.Entries), len(old.Entries))
	}
	for i, e := range got.Entries {
		v := old.Entries[i]
		if !bytes.Equal(e.Key, v.GetKey()) || !bytes.Equal(e.Msg, v.GetMsg()) || e.CacheExpirationTime != v.GetCacheExpirationTime() || e.MsgExpirationTime != v.GetMsgExpirationTime() || e.MsgStoredTime != v.GetMsgStoredTime() {
			t.Fatalf("entry %d differs: got=%+v legacy=%+v", i, e, v)
		}
	}
}

func TestDumpWireEncoderMatchesLegacyProto(t *testing.T) {
	for _, block := range []*dumpBlock{
		{}, {Entries: []*dumpEntry{nil, {}}},
		{Entries: []*dumpEntry{{Key: []byte{0, 1, 255}, Msg: []byte("dns packet"), CacheExpirationTime: -1, MsgExpirationTime: math.MinInt64, MsgStoredTime: math.MaxInt64}}},
		{Entries: []*dumpEntry{{Key: bytes.Repeat([]byte("a"), 300), MsgStoredTime: 42}, {Msg: []byte("second"), CacheExpirationTime: 4102444800}}},
	} {
		want, err := proto.Marshal(legacyDumpBlock(block))
		if err != nil {
			t.Fatal(err)
		}
		got := marshalDumpBlock(block)
		if !bytes.Equal(got, want) {
			t.Fatalf("encoded wire differs: got=%x want=%x", got, want)
		}
		assertDumpWireCompatibility(t, got)
	}
}

func TestDumpWireDecoderCompatibilityAndOwnedBytes(t *testing.T) {
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendBytes(entry, []byte("first"))
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendBytes(entry, []byte("last"))
	entry = protowire.AppendTag(entry, 3, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 99)
	entry = protowire.AppendTag(entry, 3, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 0)
	entry = protowire.AppendTag(entry, 5, protowire.BytesType) // known field, wrong wire type: unknown.
	entry = protowire.AppendBytes(entry, []byte("future"))
	entry = protowire.AppendTag(entry, 77, protowire.StartGroupType)
	entry = protowire.AppendTag(entry, 10, protowire.Fixed32Type)
	entry = protowire.AppendFixed32(entry, 100)
	entry = protowire.AppendTag(entry, 77, protowire.EndGroupType)
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, entry)
	assertDumpWireCompatibility(t, b)
	got, err := unmarshalDumpBlock(b)
	if err != nil || len(got.Entries) != 1 || string(got.Entries[0].Key) != "last" || got.Entries[0].CacheExpirationTime != 0 {
		t.Fatalf("duplicate field semantics: %+v, %v", got, err)
	}
	for i := range b {
		b[i] = 0
	}
	if string(got.Entries[0].Key) != "last" {
		t.Fatal("decoded bytes borrow pooled input memory")
	}
}

func FuzzDumpWireCompatibility(f *testing.F) {
	for _, seed := range [][]byte{
		nil, {0}, {10, 0}, {10, 2, 8, 1}, {10, 3, 24, 255, 1},
		{10, 1, 0}, {10, 3, 10, 2, 0}, {10, 2, 43, 44},
		{8, 1}, {15, 1}, {255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		protowire.AppendVarint(nil, (uint64(protowire.MaxValidNumber)+1)<<3),
		marshalDumpBlock(&dumpBlock{Entries: []*dumpEntry{{Key: []byte("cache"), Msg: []byte{0, 1, 2}, MsgStoredTime: -1}}}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) { assertDumpWireCompatibility(t, b) })
}

func BenchmarkDumpBlockEncoding(b *testing.B) {
	block := new(dumpBlock)
	for i := 0; i < dumpBlockSize; i++ {
		block.Entries = append(block.Entries, &dumpEntry{
			Key: []byte("cache.example.org."), Msg: bytes.Repeat([]byte{0, 1, 2, 3}, 128),
			CacheExpirationTime: 4102444800, MsgExpirationTime: 4102444800, MsgStoredTime: 1791456000,
		})
	}
	old := legacyDumpBlock(block)
	encodedSize := int64(len(marshalDumpBlock(block)))
	b.Run("legacy-proto", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(encodedSize)
		for b.Loop() {
			if _, err := proto.Marshal(old); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("protowire", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(encodedSize)
		for b.Loop() {
			_ = marshalDumpBlock(block)
		}
	})
}
