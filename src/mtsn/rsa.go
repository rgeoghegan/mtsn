package mtsn

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	RSA_BITS int = 128
)

// Public Exponent for any RSA math
var PublicE *big.Int = big.NewInt(int64(3))

// InvMod calculates the inverse of a mod n. Code ported from
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
func InvMod(a, n *big.Int) (*big.Int, error) {
	t := Big.Zero
	newt := Big.One
	r := n
	newr := a

	for newr.Cmp(Big.Zero) != 0 {
		quotient, rem := new(big.Int).DivMod(r, newr, new(big.Int))

		newnewt := new(big.Int)
		newnewt.Mul(quotient, newt)
		newnewt.Sub(t, newnewt)

		t, newt = newt, newnewt
		r, newr = newr, rem
	}

	if r.Cmp(Big.Two) != -1 {
		return nil, fmt.Errorf("a (%v)  %% n (%v) is not reversable", a, n)
	}

	if t.Cmp(Big.Zero) == -1 {
		t.Add(t, n)
	}
	return t, nil
}

// The client (or public) 'copy' of the RSA key which you can send out. You
// can instantiate it through RSA.Client()
type RSAClient big.Int

func (r *RSAClient) Encrypt(msg []byte) *big.Int {
	c := new(big.Int)
	c.SetBytes(msg)
	c.Exp(c, PublicE, (*big.Int)(r))
	return c
}

// RSA is the 'server' (or private) side of an RSA public-private key
// system. You should keep this object to yourself, but feel free to send
// the RSAClient to anyone.
//
// Example usage:
//
//    rsa := NewRSA()
//    client := rsa.Client()
//    encrypted := client.Encrypt(secret)
//
//    decrypted = rsa.Decrypt(encrypted)
//
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
		if err != nil {
			panic(err)
		}
		q, err = rand.Prime(rand.Reader, RSA_BITS)
		if err != nil {
			panic(err)
		}

		p1 := new(big.Int).Sub(p, Big.One)
		q1 := new(big.Int).Sub(q, Big.One)
		et = new(big.Int).Mul(p1, q1)

		rem := new(big.Int).Mod(et, Big.Three)
		if rem.Cmp(Big.Zero) != 0 {
			// If et % 3 != 0, then gcd(et, 3) == 1, so it is usable. Otherwise,
			// try with a new p and q
			break
		}
	}

	rsa.n = new(big.Int)
	rsa.n.Mul(p, q)

	rsa.d, err = InvMod(PublicE, et)
	if err != nil {
		panic(err)
	}

	return rsa
}
