package set6

import (
	"crypto/sha1"
	"fmt"
	"math/big"
	"mtsn"
)

func CrackPublicKey(dsa *DSA, publicKey *big.Int, msg []byte) *DSASignature {
	hash := sha1.Sum(msg)

	z := new(big.Int)
	z.SetBytes(hash[0:len(hash)])

	r := new(big.Int)
	r.Exp(publicKey, z, dsa.P).Mod(r, dsa.Q)

	s := InvModPanic(z, dsa.Q)
	s.Mul(s, r).Mod(s, dsa.Q)
	return &DSASignature{r, s}
}

func Challenge45() {
	dsa := NewDSA()
	// Let's set G to 0
	dsa.G = mtsn.Big.Zero
	signer := dsa.NewSigner()

	msg := []byte("It's me.")
	signature, _ := signer.SignMsg(msg)
	if mtsn.Big.Zero.Cmp(signature.R) != 0 {
		panic(fmt.Errorf("Expecting 0 as R, got %x instead", signature.R))
	}
	publicKey := signer.PublicKey()
	if !dsa.VerifySignature(publicKey, msg, signature) {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	msg = []byte("Haha, I'm also valid!")
	// Since G is 0, R is 0, and any signature validation will produce 0, no
	// matter the input string.
	if !dsa.VerifySignature(publicKey, msg, signature) {
		panic(fmt.Errorf("Cannot validate message, even with 0 R"))
	}

	// Let's set G to P + 1
	dsa.G = new(big.Int)
	dsa.G.Add(dsa.P, mtsn.Big.One)
	signer = dsa.NewSigner()

	msg = []byte("It's me.")
	signature, _ = signer.SignMsg(msg)
	// The R parameter should be 1
	if mtsn.Big.One.Cmp(signature.R) != 0 {
		panic(fmt.Errorf("Expecting 0 as R, got %x instead", signature.R))
	}

	publicKey = signer.PublicKey()
	if !dsa.VerifySignature(publicKey, msg, signature) {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	// Let's crack it
	msg = []byte("Hello, world")
	crackedSig := CrackPublicKey(dsa, publicKey, msg)
	helloValid := dsa.VerifySignature(publicKey, msg, crackedSig)
	if !helloValid {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	msg = []byte("Goodbye, world")
	crackedSig = CrackPublicKey(dsa, publicKey, msg)
	goodbyeValid := dsa.VerifySignature(publicKey, msg, crackedSig)
	if !goodbyeValid {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	fmt.Printf("Challenge 45: %v %v\n", helloValid, goodbyeValid)
}
