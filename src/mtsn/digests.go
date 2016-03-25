package mtsn

import (
	"crypto/subtle"
	"sha1hacks"
)

// Sha1Mac will produce a MAC digest of text, given a key.
func Sha1Mac(key []byte, text []byte) [20]byte {
	payload := make([]byte, len(key) + len(text))
	copy(payload, key)
	copy(payload[len(key):len(payload)], text)

	digest := sha1hacks.Sum(payload)
	return digest
}

// VerifySha1Mac will verify a Sha1 mac digest, as produced by Sha1Mac.
func VerifySha1Mac(key []byte, text []byte, origdigest [20]byte) bool {
	digest := Sha1Mac(key, text)
	return subtle.ConstantTimeCompare(digest[0:20], origdigest[0:20]) == 1
}

// Sha1Mac will produce an HMAC digest of text, given a key.
func Sha1HMAC(key []byte, text []byte) []byte {
	var paddedKey []byte
	var digest [sha1hacks.Size]byte

	if len(key) > sha1hacks.BlockSize {
		digest = sha1hacks.Sum(key)
		key = digest[0:sha1hacks.Size]
	}
	if len(key) < sha1hacks.BlockSize {
		paddedKey = make([]byte, sha1hacks.BlockSize)
		copy(paddedKey, key)
	}

	opad := make([]byte, sha1hacks.BlockSize)
	ipad := make([]byte, sha1hacks.BlockSize)
	for i := 0; i < sha1hacks.BlockSize; i++ {
		opad[i] = 0x5c
		ipad[i] = 0x36
	}

	block1 := make([]byte, len(text) + sha1hacks.BlockSize)
	copy(block1, XorBytes(paddedKey, ipad))
	copy(block1[sha1hacks.BlockSize:len(block1)], text)

	block2 := make([]byte, sha1hacks.BlockSize + sha1hacks.Size)
	copy(block2, XorBytes(paddedKey, opad))
	
	digest = sha1hacks.Sum(block1)
	copy(block2[sha1hacks.BlockSize:len(block2)], digest[0:sha1hacks.Size])
	
	digest = sha1hacks.Sum(block2)
	return digest[0:sha1hacks.Size]
}
