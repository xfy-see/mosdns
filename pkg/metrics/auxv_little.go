// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && (386 || amd64 || amd64p32 || arm || arm64 || mipsle || mips64le || loong64 || ppc64le || riscv64)

package metrics

import "encoding/binary"

func auxWord(data []byte) uint64 {
	if len(data) == 4 {
		return uint64(binary.LittleEndian.Uint32(data))
	}
	return binary.LittleEndian.Uint64(data)
}
