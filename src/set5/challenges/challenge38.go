package set5

import (
	"fmt"
	"mtsn"
	"math/big"
	"crypto/rand"
	"bytes"
)

// We use 10 passwords here for sake of speed, but this should really be a
// list of passwords from a dictionnary attack
var passwords [][]byte = [][]byte{
    []byte("123456"),
    []byte("password"),
    []byte("12345"),
    []byte("12345678"),
    []byte("qwerty"),
    []byte("123456789"),
    []byte("1234"),
    []byte("baseball"),
    []byte("dragon"),
    []byte("football"),
}

type SimpleSRPServerIntf interface {
    Step1([]byte, *big.Int)
    Step2() ([]byte, *big.Int, *big.Int)
    Step3([]byte) bool
}

type SimpleSRPServer struct {
	Salt []byte
	A *big.Int
	U *big.Int

	v *big.Int
	b *big.Int
}

func NewSimpleSRPServer(password []byte) *SimpleSRPServer {
	server := new(SimpleSRPServer)
	server.Salt = mtsn.GenerateRandomKey()
	
	x := HashStrings(server.Salt, password).Int()
	server.v = new(big.Int)
	server.v.Exp(SRP.G, x, DFConstants.P)

	var err error
	server.b, err = rand.Int(rand.Reader, DFConstants.P)
	if (err != nil) {panic(err)}

	int128 := new(big.Int).Lsh(one, 128)
	server.U, err = rand.Int(rand.Reader, int128)
	if (err != nil) {panic(err)}

	return server
}

func (s *SimpleSRPServer) Step1(email []byte, A *big.Int) {
	s.A = A
}

func (s *SimpleSRPServer) Step2() ([]byte, *big.Int, *big.Int) {
	B := new(big.Int)
	B.Exp(SRP.G, s.b, DFConstants.P)

	return s.Salt, B, s.U
}

func (s *SimpleSRPServer) Step3(clientHmac []byte) bool {
	// S = (A * v ** u)**b % n
	S := new(big.Int).Exp(s.v, s.U, DFConstants.P)
	S.Mul(S, s.A)
	S.Exp(S, s.b, DFConstants.P)

	K := HashStrings(S.Bytes())
	mac := MakeHmac(K, s.Salt)
	return bytes.Equal(clientHmac, mac)
}

type SimpleSRPClient struct {
	email []byte
	password []byte
	a *big.Int

	Salt []byte
	B *big.Int
	U *big.Int
}

func NewSimpleSRPClient(email []byte, password []byte) *SimpleSRPClient {
	client := new(SimpleSRPClient)
	client.email = email
	client.password = password

	var err error
	client.a, err = rand.Int(rand.Reader, DFConstants.P)
	if (err != nil) {panic(err)}

	return client
}

func (c *SimpleSRPClient) Step1() ([]byte, *big.Int) {
	pubA := new(big.Int)
	pubA.Exp(SRP.G, c.a, DFConstants.P)
	return c.email, pubA
}

func (c *SimpleSRPClient) Step2(salt []byte, B *big.Int, U *big.Int) {
	c.Salt = salt
	c.B = B
	c.U = U
}

func (c *SimpleSRPClient) Step3() []byte {
	x := HashStrings(c.Salt, c.password).Int()

	exp := new(big.Int)
	exp.Mul(c.U, x)
	exp.Add(c.a, exp)

	S := new(big.Int)
	S.Exp(c.B, exp, DFConstants.P)
	K := HashStrings(S.Bytes())
	return MakeHmac(K, c.Salt)

}

type MitmSimpleSRPServer struct {
	SimpleSRPServer
	clientHmac []byte
}

func (s *MitmSimpleSRPServer) Step3 (clientHmac []byte) bool {
	s.clientHmac = clientHmac
	return false
}

func (s *MitmSimpleSRPServer) CrackPassword() ([]byte, error) {
	two := big.NewInt(int64(2))

	for _, pass := range passwords {
		// with salt="", B=2, u=1,
		// x = SHA256(salt|password) = SHA256(password)
	 	// S = B**(a + ux) % n = B**a * B**ux = 2**a * 2**x = A * 2**x (mod n)
	 	// K = SHA256(S)
		// hmac = HMAC-SHA256(K, salt) = HMAC-SHA256(K, "")
		x := HashStrings(pass).Int()

		S := new(big.Int)
		S.Exp(two, x, DFConstants.P)
		S.Mul(S, s.A)
		S.Mod(S, DFConstants.P)

		K := HashStrings(S.Bytes())
		hmac := MakeHmac(K, s.Salt)

		if bytes.Equal(hmac, s.clientHmac) {
			return pass, nil
		}
	}

	return nil, fmt.Errorf("Could not crack password from list")
}

func NewMitmSimpleSRPServer() *MitmSimpleSRPServer {
	server := new(MitmSimpleSRPServer)
	server.Salt = []byte("")
	server.b = one // Server's public key will be 2**(b=1) % N == 2
	server.U = one

	return server
}

func SimpleSRPExchange(server SimpleSRPServerIntf, client *SimpleSRPClient) bool {
	email, A := client.Step1()
	server.Step1(email, A)

	salt, B, U := server.Step2()
	client.Step2(salt, B, U)

	return server.Step3(client.Step3())
}

func Challenge38() {
	// Try normally
	password := passwords[mtsn.RandomNumber(0, len(passwords))]
	client := NewSimpleSRPClient([]byte("abe@example.com"), password)
	server := NewSimpleSRPServer(password)
	normal := SimpleSRPExchange(server, client)

	// Try with MITM
	client = NewSimpleSRPClient([]byte("abe@example.com"), password)
	mitmServer := NewMitmSimpleSRPServer()
	_ = SimpleSRPExchange(mitmServer, client)
	crackedPassword, err := mitmServer.CrackPassword()
	if (err != nil) {panic(err)}

	fmt.Printf("Challenge 38: Works normally? %v mitm found password? %v.\n",
		normal, bytes.Equal(password, crackedPassword))
}
