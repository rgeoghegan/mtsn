package set6

import (
	"crypto/md5"
	"fmt"
	"math/big"
	"mtsn"
)

type RSAVerifier mtsn.RSAClient

// Given a 1024 bit signature produced by RSASigner.Sign, verifies it
// against the given text.
func (r *RSAVerifier) Verify(text []byte, digest []byte) bool {
	// Since we use big.Int for the rsa bit, it shaves off the leading 0,
	// which makes a bit of a farce of the padding, but anyway.
	decryptedI := ((*mtsn.RSAClient)(r)).Encrypt(digest)
	decrypted := decryptedI.Bytes()
	fmt.Printf("***** RORY src/set6/challenges/challenge42.go:52 decrypted %x\n", decrypted)

	if decrypted[0] != 0x00 {
		return false
	}
	if decrypted[1] != 0x01 {
		return false
	}
	if decrypted[2] != 0xff {
		return false
	}

	hasher := md5.New()
	hasher.Write(text)
	md5hash := make([]byte, hasher.Size())
	hasher.Sum(md5hash)

	return false
}

type RSASigner struct {
	rsa *mtsn.RSA
}

// Create a 1024 bit signature for the given text
func (r *RSASigner) Sign(text []byte) []byte {
	// pkcs#1 pad text
	payload := make([]byte, 112)
	payload[0] = 0x00
	payload[1] = 0x01

	for i := 2; i < 111; i++ {
		payload[i] = 0xff
	}
	payload[111] = 0x00

	hasher := md5.New()
	hasher.Write(text)
	payload = hasher.Sum(payload)
	fmt.Printf("***** RORY src/set6/challenges/challenge42.go:29 payload %x\n", payload)
	fmt.Printf("***** RORY src/set6/challenges/challenge42.go:29 key size %v\n",
		((*big.Int)(r.rsa.Client())).BitLen())

	cleartext := new(big.Int)
	cleartext.SetBytes(payload)

	return r.rsa.Decrypt(cleartext)
}

func CrackDigest(text []byte) []byte {
	return text
}

func Challenge42() {
	rsa := mtsn.NewRSA()
	signer := &RSASigner{rsa: rsa}
	verifier := (*RSAVerifier)(rsa.Client())

	text := []byte("it's me")
	digest := signer.Sign(text)

	if !verifier.Verify(text, digest) {
		panic(fmt.Errorf("Could not verify the real digest"))
	}

	crackText := []byte("hi mom")
	cracked := CrackDigest(crackText)
	if verifier.Verify(crackText, cracked) {
		fmt.Printf("Challenge42: cracked digest\n")
	} else {
		panic(fmt.Errorf("Could not crack digest :("))
	}
}
