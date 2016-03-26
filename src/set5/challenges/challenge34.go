package set5

import (
	"fmt"
	"math/big"
	"mtsn"
	"sha1hacks"
	"bytes"
)

/****
 * Code to manage Aes
 */

func EncryptPayLoad(df *DiffieHellman, publicKey *big.Int, msg []byte, iv []byte) ([]byte, error) {
	sessionKey := df.SessionKey(publicKey)
	key := sha1hacks.Sum(sessionKey.Bytes())
	payload := mtsn.PadPkcs7(msg)
	return mtsn.EncryptAesCbc(key[0:16], iv, payload)
}

func DecryptPayload(df *DiffieHellman, publicKey *big.Int, encrypted []byte, iv []byte) ([]byte, error) {
	sessionKey := df.SessionKey(publicKey)
	key := sha1hacks.Sum(sessionKey.Bytes())

	payload, err := mtsn.DecryptAesCbc(key[0:16], iv, encrypted)
	if (err != nil) {return nil, err}
	return mtsn.StripPkcs7(payload)
}

/***
 * Code for the normal DF message exchange
 */

type DFInit struct {
	P *big.Int
	G *big.Int
	Public *big.Int
}

type DFInitResponse big.Int

type Party interface {
	InitDF() *DFInit
	RespondToInit(*DFInit) (*big.Int, error)
	SendMsg(*big.Int) ([]byte, error)
	AcknowlegeMsg([]byte) ([]byte, error)
	AcknowlegeResponse([]byte) error
}

type NormalParty struct {
	df *DiffieHellman
	otherPublicKey *big.Int
	msg []byte
}

func (p *NormalParty) InitDF() *DFInit {
	resp := new(DFInit)
	resp.P = p.df.P
	resp.G = p.df.G
	resp.Public = p.df.MyPublic
	return resp
}

func (p *NormalParty) RespondToInit(init *DFInit) (*big.Int, error) {
	if (p.df != nil) {
		return nil, fmt.Errorf("RespondToInit: Already have DF initialized")
	}
	p.df = NewDiffieHellman(init.P, init.G)
	p.otherPublicKey = init.Public
	return p.df.MyPublic, nil
}

func (p *NormalParty) SendMsg(otherPublicKey *big.Int) ([]byte, error) {
	if (p.msg == nil) {
		return nil, fmt.Errorf("SendMsg: Cannot SendMsg if not initiating party.")
	}
	p.otherPublicKey = otherPublicKey

	iv := mtsn.GenerateRandomKey()
	encrypted, err := EncryptPayLoad(p.df, p.otherPublicKey, p.msg, iv)
	if (err != nil) {return nil, err}

	return append(encrypted, iv...), nil 
}

func (p *NormalParty) AcknowlegeMsg(payload []byte) ([]byte, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("AcknowlegeMsg: Cannot acknowlege message without 16 byte iv at the end")
	}
	if p.otherPublicKey == nil {
		return nil, fmt.Errorf("AcknowlegeMsg: Must have exchanged public keys beforehand")
	}

	encrypted := payload[0:len(payload)-16]
	iv := payload[len(payload)-16:len(payload)]

	msg, err := DecryptPayload(p.df, p.otherPublicKey, encrypted, iv)
	if (err != nil) {return nil, err}

	newIv := mtsn.GenerateRandomKey()
	encrypted, err = EncryptPayLoad(p.df, p.otherPublicKey, msg, newIv)
	if (err != nil) {return nil, err}

	return append(encrypted, newIv...), nil
}

func (p *NormalParty) AcknowlegeResponse(payload []byte) error {
	if len(payload) < 16 {
		fmt.Errorf("AcknowlegeResponse: Cannot acknowlege message without 16 byte iv at the end")
	}
	if p.otherPublicKey == nil {
		fmt.Errorf("AcknowlegeResponse: Must have exchanged public keys beforehand")
	}
	if p.msg == nil {
		fmt.Errorf("AcknowlegeResponse: Must be the initial party with the message")
	}

	encrypted := payload[0:len(payload)-16]
	iv := payload[len(payload)-16:len(payload)]

	msg, err := DecryptPayload(p.df, p.otherPublicKey, encrypted, iv)
	if (err != nil) {return err}

	if bytes.Compare(msg, p.msg) != 0 {
		return fmt.Errorf("AcknowlegeResponse: Received message %q does not match %q", msg, p.msg)
	}

	return nil
}

func ExchangeMessage(a Party, b Party) error {
	init := a.InitDF()

	initResp, err := b.RespondToInit(init)
	if (err != nil) {return err}

	sendMsg, err := a.SendMsg(initResp)
	if (err != nil) {return err}

	ackMsg, err := b.AcknowlegeMsg(sendMsg)
	if (err != nil) {return err}

	return a.AcknowlegeResponse(ackMsg)
}

/**
 * Code for the Man-In-The-Middle hack
 */

// Mitm is a Man-In-The-Middle for the ExhangeMessage protocol
type Mitm struct {
	partyA Party
	partyB Party
	aInit *DFInit
	msg []byte
}

func NewMITM(partyA Party, partyB Party) *Mitm {
	mitm := new(Mitm)
	mitm.partyA = partyA
	mitm.partyB = partyB
	return mitm
}

func (m *Mitm) InitDF() *DFInit {
	m.aInit = m.partyA.InitDF()
	return m.aInit
}

func (m *Mitm) RespondToInit(init *DFInit) (*big.Int, error) {
	hackedInit := new(DFInit)
	hackedInit.P = m.aInit.P
	hackedInit.G = m.aInit.G
	hackedInit.Public = m.aInit.P

	return m.partyB.RespondToInit(hackedInit)
}

func (m *Mitm) SendMsg(otherPublicKey *big.Int) ([]byte, error) {
	payload, err := m.partyA.SendMsg(m.aInit.P)
	if (err != nil) {panic(err)}

	encrypted := payload[0:len(payload)-16]
	iv := payload[len(payload)-16:len(payload)]

	// p**n mod p == 0, therefore the key is the empty []byte (as per
	// big.Int.Bytes())
	key := sha1hacks.Sum([]byte{})
	var decrypted []byte

	decrypted, err = mtsn.DecryptAesCbc(key[0:16], iv, encrypted)
	if (err != nil) {panic(err)}
	
	m.msg, err = mtsn.StripPkcs7(decrypted)
	if (err != nil) {panic(err)}

	return payload,	nil
}

func (m *Mitm) AcknowlegeMsg(payload []byte) ([]byte, error) {
	return m.partyB.AcknowlegeMsg(payload)
}

func (m *Mitm) AcknowlegeResponse(payload []byte) error {
	return m.partyA.AcknowlegeResponse(payload)
}

func Challenge34() {
	partyA := new(NormalParty)
	partyA.df = NewDiffieHellman(DFConstants.P, DFConstants.G)
	hiddenMsg := []byte("Hello B")
	partyA.msg = hiddenMsg

	partyB := new(NormalParty)

	// Normal message passing
	err := ExchangeMessage(partyA, partyB)
	if err != nil {panic(err)}

	// Now with a MITM

	// Need to re-initialize the parties
	partyA = new(NormalParty)
	partyA.df = NewDiffieHellman(DFConstants.P, DFConstants.G)
	partyA.msg = hiddenMsg

	partyB = new(NormalParty)

	mitm := NewMITM(partyA, partyB)
	err = ExchangeMessage(mitm, mitm)
	if err != nil {panic(err)}

	fmt.Printf(
		"Challenge 34: for hidden msg %q, got %q. Match? %v\n",
		hiddenMsg,
		mitm.msg,
		bytes.Compare(hiddenMsg, mitm.msg) == 0,	
	)
}
