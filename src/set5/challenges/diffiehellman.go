package set5

import (
	"math/big"
	"crypto/rand"
	"mtsn"
)

func PConstant() *big.Int {
	p := new(big.Int)
	p.SetString(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
        "fffffffffffff",
        16,
    )
    return p
}

// Constants used in Diffie Hellman exchange
var DFConstants = struct {
	P *big.Int
	G *big.Int
}{
	PConstant(),
	mtsn.Big.Two,
}

// Contains values used in one part of a Diffie-Hellman key exchange.
type DiffieHellman struct {
	P *big.Int
	G *big.Int
	MyPrivate *big.Int
	MyPublic *big.Int
}

// NewDiffieHellman sets up the neccessary parts for one of two parties in a
// Diffie-Hellman key exchange.
func NewDiffieHellman(p *big.Int, g *big.Int) *DiffieHellman{
	output := new(DiffieHellman)
	var err error

	output.P = p
	output.G = g
	output.MyPublic = new(big.Int)
	output.MyPrivate, err = rand.Int(
		rand.Reader,
		output.P,
	)
	if (err != nil) {panic(err)}

	output.MyPublic.Exp(
		output.G,
		output.MyPrivate,
		output.P,
	)

	return output
}

// SessionKey produces the session key the two parties of a Diffie-Hellman key
// exchange share.
func (d *DiffieHellman) SessionKey(otherPublic *big.Int) *big.Int {
	var session *big.Int = new(big.Int)
	session.Exp(
		otherPublic, 
		d.MyPrivate,
		d.P,
	)
	return session
}
