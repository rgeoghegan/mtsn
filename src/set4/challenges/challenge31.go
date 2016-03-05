package set4

import (
	"fmt"
	"mtsn"
	"crypto/subtle"
	"sha1hacks"
	"time"
)

type HmacVerifier struct {
	key []byte
	delay int
}

func (h *HmacVerifier) compare(text []byte, digest []byte) bool {
	realDigest := mtsn.Sha1HMAC(h.key, text)
	return (subtle.ConstantTimeCompare(digest, realDigest) == 1)
}

func (h *HmacVerifier) insecureCompare(text []byte, digest []byte) bool {
	realDigest := mtsn.Sha1HMAC(h.key, text)
	for i := 0; i < sha1hacks.Size; i++ {
		if realDigest[i] != digest[i] {
			return false
		}
		time.Sleep(time.Millisecond * time.Duration(h.delay))
	}
	return true
}

func timeRun(verifier *HmacVerifier, text []byte, prev []byte) time.Duration {
	start := time.Now()
	verifier.insecureCompare(text, prev)
	end := time.Now()
	return end.Sub(start)
}

func findByte(verifier *HmacVerifier, text []byte, pos int, prev []byte) byte {
	maxTiming := time.Duration(0)
	maxTimingByte := byte(0)

	for i := 0; i < 256; i++ {
		prev[pos] = byte(i)
		diff := timeRun(verifier, text, prev)

		if diff > maxTiming {
			maxTimingByte = byte(i)
			maxTiming = diff
		}
	}

	return maxTimingByte
}

func Challenge31() {
	key := mtsn.GenerateRandomKey()
	verifier := &HmacVerifier{key, 50}
	badFile := []byte("I am a bad file which will ruin your day")

	fakeSignature := make([]byte, sha1hacks.Size)
	for i := 0; i < sha1hacks.Size; i++ {
		fakeSignature[i] = findByte(verifier, badFile, i, fakeSignature)
	}

	fmt.Printf("Challenge 31: can fake signature? %v\n",
		verifier.compare(badFile, fakeSignature))
}