package set6

import (
	"bytes"
	"fmt"
	"math/big"
	"mtsn"
)

type Oracle struct {
	seen map[string]bool
	rsa  *mtsn.RSA
}

func (o *Oracle) Client() *mtsn.RSAClient {
	return o.rsa.Client()
}

func (o *Oracle) Decrypt(in *big.Int) ([]byte, error) {
	_, seen := o.seen[in.String()]
	if seen {
		return nil, fmt.Errorf("I have seen this ciphertext before!")
	}
	o.seen[in.String()] = true
	return o.rsa.Decrypt(in), nil

}

func Crack(oracle *Oracle, client *mtsn.RSAClient, encrypted *big.Int) []byte {
	s := mtsn.Big.Three
	n := (*big.Int)(client)

	//C' = ((S**E mod N) C) mod N
	cPrime := new(big.Int)
	cPrime.Exp(s, mtsn.PublicE, n)
	cPrime.Mul(cPrime, encrypted)
	cPrime.Mod(cPrime, n)

	pPrimeBytes, err := oracle.Decrypt(cPrime)
	if err != nil {
		panic(err)
	}
	pPrime := new(big.Int)
	pPrime.SetBytes(pPrimeBytes)

	//       P'
	// P = -----  mod N
	//      S
	p, err := mtsn.InvMod(s, n)
	if err != nil {
		panic(err)
	}
	p.Mul(p, pPrime)
	p.Mod(p, n)
	return p.Bytes()
}

func Challenge41() {
	oracle := &Oracle{seen: make(map[string]bool), rsa: mtsn.NewRSA()}
	original := []byte("secret")
	client := oracle.Client()

	encrypted := client.Encrypt(original)

	decrypted, err := oracle.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(original, decrypted) {
		panic(fmt.Errorf("First decryption got: %q", decrypted))
	}

	_, err = oracle.Decrypt(encrypted)
	if err == nil {
		panic(fmt.Errorf("Expecting error on second decryption"))
	}

	cracked := Crack(oracle, client, encrypted)
	if bytes.Equal(cracked, original) {
		fmt.Printf("Challenge41: cracked %q\n", cracked)
	} else {
		panic(fmt.Errorf("%q != %q", original, cracked))
	}
}
