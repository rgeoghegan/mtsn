package set4

import (
	"mtsn"
	"sha1hacks"
	"fmt"
	"encoding/binary"
)

const (
	LENGTH_CHECK int = 8
)

// Randomly picked words
var secretKeys = []string{"butcheress", "pseudospermium", "undoughty", "heteroclitous",
	"deneutralization", "unrecked", "electrohydraulic", "federalism", "quipsome",
	"quadrilingual"}

type AdminVerify []byte

func (a *AdminVerify) digest(text []byte) [20]byte {
	return mtsn.Sha1Mac(*a, text)
}

func (a *AdminVerify) verify(text []byte, digest [20]byte) bool {
	if ! mtsn.VerifySha1Mac(*a, text, digest) {
		return false
	}
	return mtsn.ParseAdmin(string(text))
}


func hackDigest(text []byte, digest [20]byte, keylength int) ([]byte, [20]byte) {
	originalLength := (keylength + len(text)) % 64
	paddingLength := ((56 - originalLength) + 64) % 64

	if paddingLength == 0 {
		paddingLength = 64
	}

	endPadding := make([]byte, paddingLength + LENGTH_CHECK)
	endPadding[0] = 0x80

	binary.BigEndian.PutUint64(endPadding[paddingLength:paddingLength + LENGTH_CHECK],
		uint64((len(text) + keylength) << 3))

	payload = []byte(";admin=true")
	fullTextLength := len(text) + paddingLength + LENGTH_CHECK + keylength
	newDigest := sha1hacks.HackedDigest(payload, digest, uint64(fullTextLength))

	newTextLength := len(text) + len(endPadding) + len(payload)
	newText := make([]byte, newTextLength)
	copy(newText, text)
	copy(newText[len(text):newTextLength], endPadding)
	copy(newText[len(text) + len(endPadding):newTextLength], payload)

	return newText, newDigest
}

func tryDifferentKeyLengths(admin AdminVerify, text []byte, digest [sha1hacks.Size]byte) (int, []byte, [sha1hacks.Size]byte) {
	for l := 1; l < 17; l++ {
		// Iterate for all the key lengths
		newText, newDigest := hackDigest(text, digest, l)

		if admin.verify(newText, newDigest) {
			return l, newText, newDigest
		}
	}
	panic(fmt.Errorf("Cannot find key :("))
} 

func Challenge29() {
	text := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	key := secretKeys[mtsn.RandomNumber(0, len(secretKeys))]
	adminVerify := AdminVerify(key)
	digest := adminVerify.digest(text)

	keylength, newText, newDigest := tryDifferentKeyLengths(adminVerify, text, digest)

	fmt.Printf("Challenge 29: managed to trick the admin verifier: %v, key length: %d\n",
		adminVerify.verify(newText, newDigest), keylength)
}
