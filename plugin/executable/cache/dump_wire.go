//go:build !mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// dump.proto remains the on-disk contract. The generated implementation is
// kept only in tests as an independent interoperability oracle.
type dumpEntry struct {
	Key, Msg            []byte
	CacheExpirationTime int64
	MsgExpirationTime   int64
	MsgStoredTime       int64
}

type dumpBlock struct {
	Entries []*dumpEntry
}

func marshalDumpBlock(block *dumpBlock) []byte {
	total := 0
	for _, entry := range block.Entries {
		total += protowire.SizeTag(1) + protowire.SizeBytes(sizeDumpEntry(entry))
	}
	// One block allocation, without a temporary encoded buffer per entry.
	b := make([]byte, 0, total)
	for _, entry := range block.Entries {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendVarint(b, uint64(sizeDumpEntry(entry)))
		b = appendDumpEntry(b, entry)
	}
	return b
}

func sizeDumpEntry(entry *dumpEntry) int {
	if entry == nil {
		return 0
	}
	size := 0
	for i, value := range [][]byte{entry.Key, entry.Msg} {
		if len(value) != 0 {
			size += protowire.SizeTag(protowire.Number(i+1)) + protowire.SizeBytes(len(value))
		}
	}
	for i, value := range []int64{entry.CacheExpirationTime, entry.MsgExpirationTime, entry.MsgStoredTime} {
		if value != 0 {
			size += protowire.SizeTag(protowire.Number(i+3)) + protowire.SizeVarint(uint64(value))
		}
	}
	return size
}

func appendDumpEntry(b []byte, entry *dumpEntry) []byte {
	if entry == nil {
		return b
	}
	for i, value := range [][]byte{entry.Key, entry.Msg} {
		if len(value) != 0 {
			b = protowire.AppendTag(b, protowire.Number(i+1), protowire.BytesType)
			b = protowire.AppendBytes(b, value)
		}
	}
	for i, value := range []int64{entry.CacheExpirationTime, entry.MsgExpirationTime, entry.MsgStoredTime} {
		if value != 0 {
			b = protowire.AppendTag(b, protowire.Number(i+3), protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(value))
		}
	}
	return b
}

func consumeDumpTag(b []byte) (protowire.Number, protowire.Type, int, error) {
	tag, n := protowire.ConsumeVarint(b)
	if n < 0 {
		return 0, 0, 0, protowire.ParseError(n)
	}
	field := tag >> 3
	// Check before narrowing to Number: oversized tags must not wrap to a
	// valid field number, even if protowire.ConsumeTag accepts the narrowing.
	if field < 1 || field > uint64(protowire.MaxValidNumber) {
		return 0, 0, 0, fmt.Errorf("invalid protobuf field number %d", field)
	}
	return protowire.Number(field), protowire.Type(tag & 7), n, nil
}

func unmarshalDumpBlock(b []byte) (*dumpBlock, error) {
	block := new(dumpBlock)
	for len(b) != 0 {
		num, typ, n, err := consumeDumpTag(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			value, consumed := protowire.ConsumeBytes(b)
			if consumed < 0 {
				return nil, protowire.ParseError(consumed)
			}
			entry, err := unmarshalDumpEntry(value)
			if err != nil {
				return nil, err
			}
			block.Entries = append(block.Entries, entry)
			b = b[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(num, typ, b)
		if consumed < 0 {
			return nil, protowire.ParseError(consumed)
		}
		b = b[consumed:]
	}
	return block, nil
}

func unmarshalDumpEntry(b []byte) (*dumpEntry, error) {
	entry := new(dumpEntry)
	for len(b) != 0 {
		num, typ, n, err := consumeDumpTag(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		consumed := 0
		switch {
		case (num == 1 || num == 2) && typ == protowire.BytesType:
			var value []byte
			value, consumed = protowire.ConsumeBytes(b)
			if consumed >= 0 {
				// readDump returns its pooled block buffer; fields must own bytes.
				value = append([]byte(nil), value...)
				if num == 1 {
					entry.Key = value
				} else {
					entry.Msg = value
				}
			}
		case num >= 3 && num <= 5 && typ == protowire.VarintType:
			var value uint64
			value, consumed = protowire.ConsumeVarint(b)
			if consumed >= 0 {
				switch num {
				case 3:
					entry.CacheExpirationTime = int64(value)
				case 4:
					entry.MsgExpirationTime = int64(value)
				case 5:
					entry.MsgStoredTime = int64(value)
				}
			}
		default:
			// Protobuf treats known fields with a different wire type as unknown.
			consumed = protowire.ConsumeFieldValue(num, typ, b)
		}
		if consumed < 0 {
			return nil, protowire.ParseError(consumed)
		}
		b = b[consumed:]
	}
	return entry, nil
}
