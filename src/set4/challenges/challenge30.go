package set4

import (
	"fmt"
	"md4hacks"
	//"hash"
	"mtsn"
	"bytes"
	"encoding/binary"
)

type AdminVerifyMd4 []byte

func (a *AdminVerifyMd4) digest(text []byte) []byte {
	hash := md4hacks.New()
	hash.Write(*a)
	hash.Write(text)
	return hash.Sum(nil)
}

func (a *AdminVerifyMd4) verify(text []byte, digest []byte) bool {
	if ! bytes.Equal(digest, a.digest(text)) {
		return false
	}
	return mtsn.ParseAdmin(string(text))
}

func fakePadding(keylength int, textLength int) []byte {
	totalLen := keylength + textLength
	originalLength := totalLen % 64
	len := ((56 - originalLength) + 64) % 64

	if len == 0 {
		len = 64
	}

	padding := make([]byte, len + LENGTH_CHECK)
	padding[0] = 0x80

	binary.LittleEndian.PutUint64(padding[len:len + LENGTH_CHECK],
		uint64(totalLen << 3))

	return padding
} 


func hackedDigestMd4(digest []byte, text []byte, keyLength int) ([]byte, []byte) {
	padding := fakePadding(keyLength, len(text))
	hasher := md4hacks.HackedHasher(digest, keyLength + len(text) + len(padding))
	payload := []byte(";admin=true")
	hasher.Write(payload)

	newText := make([]byte, len(text) + len(padding) + len(payload))
	copy(newText, text)
	copy(newText[len(text):len(newText)], padding)
	copy(newText[len(text)+len(padding):len(newText)], payload)

	return newText, hasher.Sum(nil)
}

func tryDifferentKeyLengthsMd4(admin *AdminVerifyMd4, digest []byte, text []byte) (int, []byte, []byte) {
	for l := 1; l < 17; l++ {
		// Iterate for all the key lengths
		newText, newDigest := hackedDigestMd4(digest, text, l)

		if admin.verify(newText, newDigest) {
			return l, newText, newDigest
		}
	}
	panic(fmt.Errorf("Cannot find key :("))
}

func Challenge30() {
	text := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	// Use the list of secret keys from challenge 29
	key := secretKeys[mtsn.RandomNumber(0, len(secretKeys))]
	
	verifier := AdminVerifyMd4(key)
	origDigest := verifier.digest(text)

	keyLength, newText, newDigest := tryDifferentKeyLengthsMd4(&verifier, origDigest, text)
	fmt.Printf("Challenge 30: managed to trick the admin verifier: %v, key length: %d\n",
		verifier.verify(newText, newDigest), keyLength)
}