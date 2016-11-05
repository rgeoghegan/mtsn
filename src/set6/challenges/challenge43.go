package set6

import (
	//"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
	"mtsn"
)

var p *big.Int = mtsn.HexBigInt(`
    800000000000000089e1855218a0e7dac38136ffafa72eda7
    859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
    2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
    ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
    b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
    1a584471bb1`)

var q *big.Int = mtsn.HexBigInt("f4f47f05794b256174bba6e9b396a7707e563c5b")

var g *big.Int = mtsn.HexBigInt(`
    5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
    458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
    322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
    0f5b64c36b625a097f1651fe775323556fe00b3608c887892
    878480e99041be601a62166ca6894bdd41a7054ec89f756ba
    9fc95302291`)

func RandomNumberBelowQ() *big.Int {
	rando := mtsn.Big.Zero
	var err error
	for rando.Cmp(mtsn.Big.Zero) == 0 {
		rando, err = rand.Int(rand.Reader, q)
		if err != nil {
			panic(err)
		}
	}
	return rando
}

type DSASigner big.Int

func (d *DSASigner) PublicKey() *big.Int {
	output := new(big.Int)
	output.Exp(g, (*big.Int)(d), p)
	return output
}

type DSASignature struct {
	R *big.Int
	S *big.Int
}

func (d *DSASigner) SignMsg(msg []byte) (*DSASignature, *big.Int) {
	for {
		k := RandomNumberBelowQ()

		r := new(big.Int)
		r.Exp(g, k, p)
		r.Mod(r, q)

		if r.Cmp(mtsn.Big.Zero) == 0 {
			continue
		}

		kInv, err := mtsn.InvMod(k, q)
		if err != nil {
			continue
		}
		xr := new(big.Int).Mul((*big.Int)(d), r)

		hash := sha1.Sum(msg)
		s := new(big.Int)
		s.SetBytes(hash[0:len(hash)])
		s.Add(s, xr).Mul(s, kInv).Mod(s, q)

		if s.Cmp(mtsn.Big.Zero) == 0 {
			continue
		}
		return &DSASignature{r, s}, k
	}
}

func VerifySignature(pk *big.Int, msg []byte, sig *DSASignature) bool {
	if sig.R.Cmp(mtsn.Big.Zero) == 0 {
		return false
	}
	if sig.S.Cmp(mtsn.Big.Zero) == 0 {
		return false
	}

	w, err := mtsn.InvMod(sig.S, q)
	if err != nil {
		panic(err)
	}

	hash := sha1.Sum(msg)
	u1 := new(big.Int)
	u1.SetBytes(hash[0:len(hash)]).Mul(u1, w).Mod(u1, q)

	u2 := new(big.Int)
	u2.Mul(sig.R, w).Mod(u2, q)

	u1.Exp(g, u1, p)
	u2.Exp(pk, u2, p)
	v := new(big.Int)
	v.Mul(u1, u2).Mod(v, p).Mod(v, q)

	return v.Cmp(sig.R) == 0
}

type DSACracker struct {
	msg  []byte
	sig  *DSASignature
	hash *big.Int
	rInv *big.Int
}

func (c *DSACracker) CrackWithLeakedK(k *big.Int) *big.Int {
	x := new(big.Int)
	return x.Mul(c.sig.S, k).Sub(x, c.hash).Mul(x, c.rInv).Mod(x, q)
}

func NewDSACracker(msg []byte, sig *DSASignature) *DSACracker {
	hash := sha1.Sum(msg)
	h := new(big.Int)
	h.SetBytes(hash[0:len(hash)])

	rInv, err := mtsn.InvMod(sig.R, q)
	if err != nil {
		panic(err)
	}

	return &DSACracker{msg, sig, h, rInv}
}

func CrackWithLimitedK(cracker *DSACracker) *big.Int {
	maxK := int64(1 << 16)

	for i := int64(0); i < maxK; i++ {
		k := big.NewInt(i)
		x := cracker.CrackWithLeakedK(k)

		testR := new(big.Int)
		testR = testR.Exp(g, k, p).Mod(testR, q)

		if testR.Cmp(cracker.sig.R) == 0 {
			return x
		}
	}
	panic(fmt.Errorf("Cannot find matching k below %d?", maxK))
}

func Challenge43() {
	var signer *DSASigner = (*DSASigner)(RandomNumberBelowQ())

	msg := []byte("It's me.")
	signature, leakedK := signer.SignMsg(msg)
	publicKey := signer.PublicKey()

	if !VerifySignature(publicKey, msg, signature) {
		panic(fmt.Errorf("Cannot validate signed message"))
	}

	// Try with leaked k
	cracker := NewDSACracker(msg, signature)
	crackedSecretKey := cracker.CrackWithLeakedK(leakedK)
	if crackedSecretKey.Cmp((*big.Int)(signer)) != 0 {
		panic(fmt.Errorf("Could not crack key with leaked K"))
	}

	// Try to crack the given signature
	msg = []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")

	r := new(big.Int)
	fmt.Sscanf("548099063082341131477253921760299949438196259240", "%d", r)
	s := new(big.Int)
	fmt.Sscanf("857042759984254168557880549501802188789837994940", "%d", s)
	signature = &DSASignature{r, s}

	cracker = NewDSACracker(msg, signature)
	crackedSecretKey = CrackWithLimitedK(cracker)
	asHexBytes := []byte(fmt.Sprintf("%x", crackedSecretKey.Bytes()))
	fingerprint := sha1.Sum(asHexBytes)
	if "0954edd5e0afe5542a4adf012611a91912a3ec16" != fmt.Sprintf("%x", fingerprint) {
		panic(fmt.Errorf("Got %x as a fingerprint", fingerprint))
	}

	fmt.Printf("Challenge43: 0x%x\n", crackedSecretKey)
}
