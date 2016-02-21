package sha1hacks

import "encoding/binary"

var block = blockGeneric

func HackedDigest(data []byte, prevDigest [Size]byte, length uint64) [Size]byte{
	var d digest
	d.len = length

	for i := 0; i < Size; i +=4 {
		d.h[i/4] = binary.BigEndian.Uint32(prevDigest[i:i+4])
	}

	d.Write(data)
	return d.checkSum()
}
