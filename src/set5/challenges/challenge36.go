package set5

import (
	"mtsn"
	"fmt"
	"math/big"
	"crypto/sha256"
	"crypto/rand"
	"crypto/hmac"
)

// Constants used in a Secure Remote Password exchange
var SRP = struct {
	G *big.Int
	K *big.Int
}{
	big.NewInt(int64(2)),
	big.NewInt(int64(3)),
}

type HashSha256 []byte

func (h HashSha256) Int() *big.Int {
	res := new(big.Int)
	res.SetBytes(h)
	return res
}

// func (h HashSha256) Equal(other HashSha256) bool {
// 	return subtle.ConstantTimeCompare(h, other) == 1
// }

func HashStrings(strings ...[]byte) HashSha256 {
	hash := sha256.New()

	for _, elem := range strings {
		hash.Write(elem)	
	}

	res := make([]byte, 0, sha256.Size)
	return hash.Sum(res)
}

func HashTwoInts(a,b  *big.Int) HashSha256 {
	return HashStrings(a.Bytes(), b.Bytes())
}

type SRPClientIntf interface {
    Step1(server *SRPServer)
    Step2(salt []byte, pubB *big.Int)
    Step3()
    Step4() []byte
}

type SRPClient struct {
	email []byte
	password []byte

	a *big.Int
	pubA *big.Int
	B *big.Int
	Salt []byte
	K []byte
}


func NewSRPClient(email []byte, password []byte) *SRPClient {
	var err error

	c := new(SRPClient)
	c.email = email
	c.password = password

	c.a, err = rand.Int(rand.Reader, DFConstants.P)
	if (err != nil) {panic(err)}

	return c
}

type SRPServer struct {
	salt []byte
	email []byte
	password []byte
	v *big.Int
	b *big.Int
	pubB *big.Int
	k []byte

	A *big.Int
}

func NewSRPServer(password []byte) *SRPServer {
	res := new(SRPServer)
	res.salt = mtsn.GenerateRandomKey()
	res.password = password

	x := HashStrings(res.salt, res.password)

	res.v = new(big.Int)
	res.v.Exp(SRP.G, x.Int(), DFConstants.P)

	var err error
	res.b, err = rand.Int(rand.Reader, DFConstants.P)
	if (err != nil) {panic(err)}

	return res
}

func (c *SRPClient) Step1(server *SRPServer) {
	server.email = c.email

	c.pubA = new(big.Int)
	c.pubA.Exp(SRP.G, c.a, DFConstants.P)
	server.A = c.pubA
}

func (s *SRPServer) Step2(client SRPClientIntf) {
	// B = kv + g**b % N
	i := new(big.Int)
	i.Exp(SRP.G, s.b, DFConstants.P)
	
	s.pubB = new(big.Int)
	s.pubB.Mul(s.v, SRP.K)
	s.pubB.Add(s.pubB, i)

    client.Step2(s.salt, s.pubB)
}

func (c *SRPClient) Step2(salt []byte, pubB *big.Int) {
    c.Salt = salt
    c.B = pubB
}

func (s *SRPServer) Step3() {
	u := HashTwoInts(s.A, s.pubB).Int()

	// (A * v**u) ** b % N
	S := new(big.Int)
	S.Exp(s.v, u, DFConstants.P) 	// I can mod N here because the final
									// calculation is also mod N
	S.Mul(S, s.A)

	// We hit this bug (https://github.com/golang/go/issues/13973) in
	// challenge 37 when s.A is equal to the NIST prime, so we throw an extra
	// Mod here to try and reduce the size of the numbers
	S.Mod(S, DFConstants.P)
	S.Exp(S, s.b, DFConstants.P)

	s.k = HashStrings(S.Bytes())
}

func (c *SRPClient) Step3() {
	u := HashTwoInts(c.pubA, c.B).Int()
	x := HashStrings(c.Salt, c.password).Int()

	// S = (B - k * g**x)**(a + u * x) % N
	e := new(big.Int)
	e.Mul(u, x)
	e.Add(e, c.a)

	S := new(big.Int)
	S.Exp(SRP.G, x, DFConstants.P)
	S.Mul(S, SRP.K)
	S.Sub(c.B, S)
	S.Exp(S, e, DFConstants.P)

	c.K = HashStrings(S.Bytes())
}

func (c *SRPClient) Step4() []byte {
	mac := hmac.New(sha256.New, c.K)
	return mac.Sum(c.Salt)
}

func (s *SRPServer) Step5(digest []byte) bool {
	mac := hmac.New(sha256.New, s.k)
	return hmac.Equal(mac.Sum(s.salt), digest)
}

func SRPExchange(server *SRPServer, client SRPClientIntf) bool {
	client.Step1(server)
	server.Step2(client)

	client.Step3()
	server.Step3()

	return server.Step5(client.Step4())
}

func Challenge36() {
	client := NewSRPClient([]byte("abe@example.com"), []byte("password"))
	server := NewSRPServer([]byte("password"))
	fmt.Printf("Challenge 36: Successfully exchanged? %v\n", SRPExchange(server, client))
}
