package mtsn

import (
	"crypto/subtle"
	"sha1hacks"
)

func Sha1Mac(key []byte, text []byte) [20]byte {
	payload := make([]byte, len(key) + len(text))
	copy(payload, key)
	copy(payload[len(key):len(payload)], text)

	digest := sha1hacks.Sum(payload)
	return digest
}

func VerifySha1Mac(key []byte, text []byte, origdigest [20]byte) bool {
	digest := Sha1Mac(key, text)
	return subtle.ConstantTimeCompare(digest[0:20], origdigest[0:20]) == 1
}
