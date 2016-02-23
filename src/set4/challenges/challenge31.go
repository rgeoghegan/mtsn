package set4

import (
	"fmt"
	"mtsn"
	"crypto/subtle"
	"sha1hacks"
	"time"
)

type HmacVerifier []byte

func (h *HmacVerifier) compare(text []byte, digest []byte) bool {
	realDigest := mtsn.Sha1HMAC(*h, text)
	return (subtle.ConstantTimeCompare(digest, realDigest) == 1)
}

func (h *HmacVerifier) insecure_compare(text []byte, digest []byte) bool {
	realDigest := mtsn.Sha1HMAC(*h, text)
	for i := 0; i < sha1hacks.Size; i++ {
		if realDigest[i] != digest[i] {
			return false
		}
		time.Sleep(time.Millisecond * 50)
	}
	return true
}

func findByte(verifier HmacVerifier, text []byte, pos int, prev []byte) byte {
	maxTiming := time.Duration(0)
	maxTimingByte := byte(0)

	for i := 0; i < 256; i++ {
		prev[pos] = byte(i)
		start := time.Now()
		verifier.insecure_compare(text, prev)
		end := time.Now()
		diff := end.Sub(start)

		if diff > maxTiming {
			maxTimingByte = byte(i)
			maxTiming = diff
		}
	}

	return maxTimingByte
}

func findSignature(verifier HmacVerifier, content []byte) []byte {
	prev := make([]byte, sha1hacks.Size)

	for i := 0; i < sha1hacks.Size; i++ {
		prev[i] = findByte(verifier, content, i, prev)
	}
	return prev
}

func Challenge31() {
	key := mtsn.GenerateRandomKey()
	verifier := HmacVerifier(key)
	badFile := []byte("I am a bad file which will ruin your day")

	fakeSignature := findSignature(verifier, badFile)

	fmt.Printf("Challenge 31: can fake signature? %v\n",
		verifier.compare(badFile, fakeSignature))
}