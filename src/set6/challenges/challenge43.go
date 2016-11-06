package set6

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
	"mtsn"
)

var p string = `
    800000000000000089e1855218a0e7dac38136ffafa72eda7
    859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
    2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
    ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
    b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
    1a584471bb1`

var q string = "f4f47f05794b256174bba6e9b396a7707e563c5b"

var g string = `
    5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
    458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
    322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
    0f5b64c36b625a097f1651fe775323556fe00b3608c887892
    878480e99041be601a62166ca6894bdd41a7054ec89f756ba
    9fc95302291`

type DSA struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func (d *DSA) RandomNumberBelowQ() *big.Int {
	rando := mtsn.Big.Zero
	var err error
	for rando.Cmp(mtsn.Big.Zero) == 0 {
		rando, err = rand.Int(rand.Reader, d.Q)
		if err != nil {
			panic(err)
		}
	}
	return rando
}

func (d *DSA) NewSigner() *DSASigner {
	return &DSASigner{d, d.RandomNumberBelowQ()}
}

func (d *DSA) VerifySignature(publicKey *big.Int, msg []byte, sig *DSASignature) bool {
	w := InvModPanic(sig.S, d.Q)
	hash := sha1.Sum(msg)
	u1 := new(big.Int)
	u1.SetBytes(hash[0:len(hash)]).Mul(u1, w).Mod(u1, d.Q)

	u2 := new(big.Int)
	u2.Mul(sig.R, w).Mod(u2, d.Q)

	u1.Exp(d.G, u1, d.P)
	u2.Exp(publicKey, u2, d.P)
	v := new(big.Int)
	v.Mul(u1, u2).Mod(v, d.P).Mod(v, d.Q)

	return v.Cmp(sig.R) == 0
}

func NewDSA() *DSA {
	return &DSA{
		mtsn.HexBigInt(p),
		mtsn.HexBigInt(q),
		mtsn.HexBigInt(g),
	}
}

type DSASigner struct {
	dsa        *DSA
	privateKey *big.Int
}

func (d *DSASigner) PublicKey() *big.Int {
	output := new(big.Int)
	output.Exp(d.dsa.G, d.privateKey, d.dsa.P)
	return output
}

type DSASignature struct {
	R *big.Int
	S *big.Int
}

func (d *DSASigner) SignMsg(msg []byte) (*DSASignature, *big.Int) {
	for {
		k := d.dsa.RandomNumberBelowQ()

		r := new(big.Int)
		r.Exp(d.dsa.G, k, d.dsa.P)
		r.Mod(r, d.dsa.Q)

		kInv := InvModPanic(k, d.dsa.Q)
		xr := new(big.Int).Mul(d.privateKey, r)

		hash := sha1.Sum(msg)
		s := new(big.Int)
		s.SetBytes(hash[0:len(hash)])
		s.Add(s, xr).Mul(s, kInv).Mod(s, d.dsa.Q)

		return &DSASignature{r, s}, k
	}
}

type DSACracker struct {
	dsa  *DSA
	msg  []byte
	sig  *DSASignature
	hash *big.Int
	rInv *big.Int
}

func (c *DSACracker) CrackWithLeakedK(k *big.Int) *big.Int {
	x := new(big.Int)
	return x.Mul(c.sig.S, k).Sub(x, c.hash).Mul(x, c.rInv).Mod(x, c.dsa.Q)
}

func NewDSACracker(dsa *DSA, msg []byte, sig *DSASignature) *DSACracker {
	hash := sha1.Sum(msg)
	h := new(big.Int)
	h.SetBytes(hash[0:len(hash)])

	rInv := InvModPanic(sig.R, dsa.Q)
	return &DSACracker{dsa, msg, sig, h, rInv}
}

func (c *DSACracker) CrackWithLimitedK() *big.Int {
	maxK := int64(1 << 16)

	for i := int64(0); i < maxK; i++ {
		k := big.NewInt(i)
		x := c.CrackWithLeakedK(k)

		testR := new(big.Int)
		testR = testR.Exp(c.dsa.G, k, c.dsa.P).Mod(testR, c.dsa.Q)

		if testR.Cmp(c.sig.R) == 0 {
			return x
		}
	}
	panic(fmt.Errorf("Cannot find matching k below %d?", maxK))
}

// Given a big.Int, returns the hex version of the sha1 hash of the hex
// version of that number
func Sha1HexRepr(n *big.Int) string {
	asHexBytes := []byte(fmt.Sprintf("%x", n.Bytes()))
	fingerprint := sha1.Sum(asHexBytes)
	return fmt.Sprintf("%x", fingerprint)
}

func Challenge43() {
	dsa := NewDSA()
	signer := dsa.NewSigner()

	msg := []byte("It's me.")
	signature, leakedK := signer.SignMsg(msg)
	publicKey := signer.PublicKey()

	if !dsa.VerifySignature(publicKey, msg, signature) {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	// Try with leaked k
	cracker := NewDSACracker(dsa, msg, signature)
	crackedSecretKey := cracker.CrackWithLeakedK(leakedK)
	if crackedSecretKey.Cmp(signer.privateKey) != 0 {
		panic(fmt.Errorf("Could not crack key with leaked K"))
	}

	// Try to crack the given signature
	msg = []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")

	r := new(big.Int)
	fmt.Sscanf("548099063082341131477253921760299949438196259240", "%d", r)
	s := new(big.Int)
	fmt.Sscanf("857042759984254168557880549501802188789837994940", "%d", s)
	signature = &DSASignature{r, s}

	cracker = NewDSACracker(dsa, msg, signature)
	crackedSecretKey = cracker.CrackWithLimitedK()
	fingerprint := Sha1HexRepr(crackedSecretKey)
	if "0954edd5e0afe5542a4adf012611a91912a3ec16" != fingerprint {
		panic(fmt.Errorf("Got %x as a fingerprint", fingerprint))
	}

	fmt.Printf("Challenge43: 0x%x\n", crackedSecretKey)
}
