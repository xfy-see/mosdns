// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && (mips || mips64 || ppc64 || s390x)

package metrics

import "encoding/binary"

func auxWord(data []byte) uint64 {
	if len(data) == 4 {
		return uint64(binary.BigEndian.Uint32(data))
	}
	return binary.BigEndian.Uint64(data)
}
