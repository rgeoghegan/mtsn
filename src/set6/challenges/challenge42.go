package set6

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/ALTree/bigfloat"
	"math/big"
	"mtsn"
)

type RSAVerifier mtsn.RSAClient

// Given a 1024 bit signature produced by RSASigner.Sign, verifies it
// against the given text.
func (r *RSAVerifier) Verify(text []byte, digest []byte) bool {
	decryptedI := ((*mtsn.RSAClient)(r)).Encrypt(digest)
	// Since we use big.Int for the rsa bit, it shaves off the leading 0,
	// which makes a bit of a farce of the padding, but anyway.
	decrypted := append([]byte{0x00}, decryptedI.Bytes()...)

	if decrypted[0] != 0x00 {
		return false
	}
	if decrypted[1] != 0x01 {
		return false
	}
	if decrypted[2] != 0xff {
		return false
	}
	var i int
	for i = 3; i < len(decrypted); i++ {
		if decrypted[i] != 0xff {
			break
		}
	}
	if decrypted[i] != 0x00 {
		return false
	}
	i++
	receivedHash := decrypted[i : i+16]
	expectedHash := md5.Sum(text)
	return bytes.Equal(expectedHash[0:md5.Size], receivedHash)
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

	cleartext := new(big.Int)
	cleartext.SetBytes(payload)

	return r.rsa.Decrypt(cleartext)
}

// Returns the closes interger equal or below the cubic root of n
func CubeRoot(n *big.Int) *big.Int {
	base := new(big.Float)
	base.SetInt(n)
	exp := big.NewFloat(1.0)
	exp = exp.Quo(exp, big.NewFloat(3.0))
	approx := new(big.Int)
	bigfloat.Pow(base, exp).Int(approx)

	for i := int64(0); ; i++ {
		newApprox := new(big.Int)
		newApprox.Add(big.NewInt(i), approx)
		cube := new(big.Int)
		cube.Mul(newApprox, newApprox)
		cube.Mul(cube, newApprox)

		switch cube.Cmp(n) {
		case 0:
			return newApprox
		case 1:
			return approx.Add(approx, big.NewInt(i-1))
			// -1 just continues the loop
		}
	}
}

type Cracker struct {
	payload *big.Int
	target  *big.Int
}

func (c *Cracker) ShiftBigger() {
	c.payload.Lsh(c.payload, 0x4)
}

func (c *Cracker) ShiftSmaller() {
	c.payload.Rsh(c.payload, 0x4)
}

func (c *Cracker) SetHalfByte(hb int64) {
	c.ShiftSmaller()
	c.ShiftBigger()
	c.payload.Add(c.payload, big.NewInt(hb))
}

func (c *Cracker) Check() int {
	cube := new(big.Int)
	cube.Mul(c.payload, c.payload).Mul(cube, c.payload)

	cube.Rsh(cube, uint(cube.BitLen()-c.target.BitLen()))
	cmp := cube.Cmp(c.target)

	return cmp
}

func (c *Cracker) Step() bool {
	c.ShiftBigger()

	var bottom, top, middle int64 = 0x0, 0x10, 0x0
	for (top - bottom) > 1 {
		middle = ((top - bottom) / 2) + bottom
		c.SetHalfByte(middle)
		switch c.Check() {
		case -1:
			bottom = middle
		case 0:
			return false
		case 1:
			top = middle
		}
	}
	c.SetHalfByte(bottom)
	return true
}

func CrackDigest(text []byte) []byte {
	// Initialize cracker
	target := []byte{0x01, 0x0ff, 0x00}
	hash := md5.Sum(text)
	target = append(target, hash[0:md5.Size]...)

	cracker := &Cracker{target: new(big.Int)}
	cracker.target.SetBytes(target)
	cracker.payload = CubeRoot(cracker.target)

	switch cracker.Check() {
	case -1:
		// Loop steps
		for i := 0; cracker.Step() && i < 30; i++ {}
	case 1:
		panic(fmt.Errorf("Initial cube too big :("))
	}

	if (cracker.payload.BitLen()-1)%8 > 0 {
		// The first byte is 0x01 (so we remove it), but make sure the rest is byte-aligned
		cracker.ShiftBigger()
	}

	return cracker.payload.Bytes()
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
