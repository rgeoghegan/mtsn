package md4hacks

import (
	"encoding/binary"
	"hash"
)

func HackedHasher(prevDigest []byte, length int) hash.Hash {
	d := new(digest)
	d.len = uint64(length)

	for i := 0; i < Size; i +=4 {
		d.s[i/4] = binary.LittleEndian.Uint32(prevDigest[i:i+4])
	}
	return d
}