package set5

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"bytes"
	"mtsn"
)

const (
	RSA_BITS int = 128
)

var pubE *big.Int = big.NewInt(int64(3))

// Code ported from https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
func InvMod(a, n *big.Int) (*big.Int, error) {
	t := mtsn.Big.Zero
	newt := mtsn.Big.One
	r := n
	newr := a

	for ; newr.Cmp(mtsn.Big.Zero) != 0; {
		quotient, rem := new(big.Int).DivMod(r, newr, new(big.Int))

		newnewt := new(big.Int)
		newnewt.Mul(quotient, newt)
		newnewt.Sub(t, newnewt)

		t, newt = newt, newnewt
		r, newr = newr, rem
	}

	if r.Cmp(mtsn.Big.Two) != -1 {
		return nil, fmt.Errorf("a (%v)  %% n (%v) is not reversable", a, n)
	}

	if t.Cmp(mtsn.Big.Zero) == -1 {
		t.Add(t, n)
	}
	return t, nil
}

type RSAClient big.Int

func (r *RSAClient) Encrypt(msg []byte) *big.Int {
	c := new(big.Int)
	c.SetBytes(msg)
	c.Exp(c, pubE, (*big.Int)(r))
	return c
}

type RSA struct {
	n *big.Int
	d *big.Int
}

func (r *RSA) Client() *RSAClient {
	return (*RSAClient)(r.n)
}

func (r *RSA) Decrypt(encrypted *big.Int) []byte {
	msg := new(big.Int)
	msg.Exp(encrypted, r.d, r.n)
	return msg.Bytes()
}

func NewRSA() *RSA {
	rsa := new(RSA)

	var p, q, et *big.Int
	var err error

	for {
		p, err = rand.Prime(rand.Reader, RSA_BITS)
		if (err != nil) {panic(err)}
		q, err = rand.Prime(rand.Reader, RSA_BITS)
		if (err != nil) {panic(err)}

		p1 := new(big.Int).Sub(p, mtsn.Big.One)
		q1 := new(big.Int).Sub(q, mtsn.Big.One)
		et = new(big.Int).Mul(p1, q1)

		rem := new(big.Int).Mod(et, mtsn.Big.Three)
		if rem.Cmp(mtsn.Big.Zero) != 0 {
			// If et % 3 != 0, then gcd(et, 3) == 1, so it is usable. Otherwise,
			// try with a new p and q
			break
		}
	}

	rsa.n = new(big.Int)
	rsa.n.Mul(p, q)

	rsa.d, err = InvMod(pubE, et)
	if (err != nil) {panic(err)}

	return rsa
}

func Challenge39() {
	rsa := NewRSA()
	client := rsa.Client()
	msg := []byte("hello")

	encrypted := client.Encrypt(msg)
	decrypted := rsa.Decrypt(encrypted)

	fmt.Printf("Challenge 39: decrypted %q match? %v\n",
		decrypted, bytes.Equal(msg, decrypted))
}