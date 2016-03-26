package set5

import (
	"bytes"
	"fmt"
	"math/big"
	"sha1hacks"
	"mtsn"
)

var zero *big.Int = big.NewInt(int64(0))
var one *big.Int = big.NewInt(int64(1))

// HackGMitm is a Man-In-The-Middle which let's you play around with the value
// for G within the ExhangeMessage protocol
type HackGMitm struct {
	Mitm
	g *big.Int

	partyAPublic *big.Int
	fakeSessionKey *big.Int
}

func NewHackGMitm(partyA Party, partyB Party, g *big.Int) *HackGMitm {
	mitm := new(HackGMitm)
	mitm.partyA = partyA
	mitm.partyB = partyB
	mitm.g = g
	return mitm
}

func (m *HackGMitm) RespondToInit(init *DFInit) (*big.Int, error) {
	hackedInit := new(DFInit)
	hackedInit.P = m.aInit.P
	hackedInit.G = m.g

	// We set the public key to G such that partyB will also have the same
	// session key
	hackedInit.Public = m.partyAPublic

	return m.partyB.RespondToInit(hackedInit)
}

func (m *HackGMitm) SendMsg(otherPublicKey *big.Int) ([]byte, error) {
	payload, err := m.partyA.SendMsg(otherPublicKey)
	if (err != nil) {panic(err)}

	encrypted := payload[0:len(payload)-16]
	iv := payload[len(payload)-16:len(payload)]

	key := sha1hacks.Sum(m.fakeSessionKey.Bytes())
	var decrypted []byte

	decrypted, err = mtsn.DecryptAesCbc(key[0:16], iv, encrypted)
	if (err != nil) {panic(err)}
	
	m.msg, err = mtsn.StripPkcs7(decrypted)
	if (err != nil) {panic(err)}

	return payload,	nil
}

/**
 * Specific Mitm hack for when g = p - 1
 */
type HackGMitmEven struct {
	HackGMitm
}

func NewHackGMitmEven(partyA Party, partyB Party) *HackGMitmEven {
	mitm := new(HackGMitmEven)
	mitm.partyA = partyA
	mitm.partyB = partyB
	mitm.g = new(big.Int)
	mitm.g.Sub(DFConstants.P, one)
	return mitm
}

func (m *HackGMitmEven) SendMsg(otherPublicKey *big.Int) ([]byte, error) {
	payload, err := m.partyA.SendMsg(otherPublicKey)
	if (err != nil) {panic(err)}

	encrypted := payload[0:len(payload)-16]
	iv := payload[len(payload)-16:len(payload)]

	// Assume a*b is even
	var decrypted []byte
	evenKey := sha1hacks.Sum(one.Bytes())
	
	decrypted, err = mtsn.DecryptAesCbc(evenKey[0:16], iv, encrypted)
	if (err != nil) {panic(err)}
	
	decrypted, err = mtsn.StripPkcs7(decrypted)
	if (err != nil) {
		// The even key did not work, let's try the odd key
		oddKey := sha1hacks.Sum(m.g.Bytes())
		decrypted, err = mtsn.DecryptAesCbc(oddKey[0:16], iv, encrypted)
		if (err != nil) {panic(err)}
	
		decrypted, err = mtsn.StripPkcs7(decrypted)
		if (err != nil) {panic(err)}
	}
	m.msg = decrypted

	return payload,	nil
}

func Challenge35() {
	var matches [3]bool
	var err error
	var partyA, partyB *NormalParty
	var mitm *HackGMitm
	hiddenMsg := []byte("Hello B")

	// Init the parties
	partyA = new(NormalParty)
	partyA.df = NewDiffieHellman(DFConstants.P, DFConstants.G)
	partyA.msg = hiddenMsg
	partyB = new(NormalParty)

	// Try with g == 1
	mitm = NewHackGMitm(partyA, partyB, one)

	// A = g^a mod p
	// B = 1^b mod p = 1
	// Sa = 1^a mod p = 1
	// If we give partyB 1 for the public key for partyA, they will share 1 as
	// the same session key
	mitm.partyAPublic = one
	mitm.fakeSessionKey = one

	// Note that I'm too lazy to implement the step two ACK in the challenge
	// description as the protocol defined in challenge 34 does the same
	// thing.
	err = ExchangeMessage(mitm, mitm)
	if err != nil {panic(err)}
	matches[0] = bytes.Compare(hiddenMsg, mitm.msg) == 0

	// Re-init the parties
	partyA = new(NormalParty)
	partyA.df = NewDiffieHellman(DFConstants.P, DFConstants.G)
	partyA.msg = hiddenMsg
	partyB = new(NormalParty)

	// Try with g == p
	mitm = NewHackGMitm(partyA, partyB, DFConstants.P)

	// A = g^a mod p
	// B = 0^b mod p = 0
	// Sa = 0^a mod p = 0
	// If we give partyB 0 for the public key for partyA, they will share 0 as
	// the same session key
	mitm.partyAPublic = zero
	mitm.fakeSessionKey = zero

	err = ExchangeMessage(mitm, mitm)
	if err != nil {panic(err)}
	matches[1] = bytes.Compare(hiddenMsg, mitm.msg) == 0

	// Re-init the parties
	partyA = new(NormalParty)
	partyA.df = NewDiffieHellman(DFConstants.P, DFConstants.G)
	partyA.msg = hiddenMsg
	partyB = new(NormalParty)

	// Try with g == p - 1
	
	// A = g^a mod p
	// B = (p-1)^b mod p = -1^b mod p
	// Sa = B^a mod p = (-1^b)^a mod p = -1^(a*b) mod p
	// Which can be of two values, depending on if a*b is even. If a*b is even
	// (75% of the cases!), Sa = 1. If a * b is odd, Sa = p - 1
	// We can assume that a*b is even, try both assumptions in SendMsg, and if
	// we are wrong, we can still get the message but the exchange will fail.
	mitmEven := NewHackGMitmEven(partyA, partyB)

	// We don't care if the exchange succeds.
	_ = ExchangeMessage(mitmEven, mitmEven)
	matches[2] = bytes.Compare(hiddenMsg, mitm.msg) == 0

	fmt.Printf("Challenge 35: Found messages? %v\n", matches)
}