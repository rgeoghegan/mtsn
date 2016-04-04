package set5

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"mtsn"
)

type SRPHackedClient struct {
    SRPClient
}

func NewSRPHackedClient(email []byte, pubA *big.Int, k *big.Int) *SRPHackedClient {
	var err error

	c := new(SRPHackedClient)
	c.email = email
	c.pubA = pubA

	c.a, err = rand.Int(rand.Reader, DFConstants.P)
	if (err != nil) {panic(err)}

	c.K = HashStrings(k.Bytes())

	return c
}

func (c *SRPHackedClient) Step1(server *SRPServer) {
	server.email = c.email
	server.A = c.pubA
}

func (c *SRPHackedClient) Step3() {}

func Challenge37() {
	var results [3]bool

	// client public key is 0
	client := NewSRPHackedClient(
		[]byte("abe@example.com"),
		mtsn.Big.Zero,
		mtsn.Big.Zero,
	)
	server := NewSRPServer([]byte("password"))
	results[0] = SRPExchange(server, client)

	// client public key is N
	client = NewSRPHackedClient(
		[]byte("abe@example.com"),
		DFConstants.P,
		mtsn.Big.Zero,
	)
	server = NewSRPServer([]byte("password"))
	results[1] = SRPExchange(server, client)

	// client public key is 2*N
	publicKey := new(big.Int)
	publicKey.Add(DFConstants.P, DFConstants.P)
	client = NewSRPHackedClient(
		[]byte("abe@example.com"),
		publicKey,
		mtsn.Big.Zero,
	)
	server = NewSRPServer([]byte("password"))
	results[2] = SRPExchange(server, client)

	fmt.Printf("Challenge 37: Logged in each time? %v\n", results)
}
