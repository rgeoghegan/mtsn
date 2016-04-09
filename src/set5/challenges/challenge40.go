package set5

import (
	"math/big"
	"fmt"
	"bytes"
	"mtsn"
)

func BinarySearchCubeRoot(n *big.Int) (*big.Int, error) {
	top := new(big.Int)
	top.Div(n, mtsn.Big.Two)
	delta := new(big.Int)
	delta.Div(top, mtsn.Big.Two)

	for {
		cube := new(big.Int)
		cube.Mul(top, top)
		cube.Mul(cube, top)

		switch cube.Cmp(n) {
			case -1 :
				top.Add(top, delta)
			case 0:
				return top, nil
			case 1:
				top.Sub(top, delta)
		}

		if delta.Cmp(mtsn.Big.One) == 0 {
			return nil, fmt.Errorf("Cannot cube %v", n)
		}
		isDeltaOdd := delta.Bit(0) == 1
		delta.Div(delta, mtsn.Big.Two)
		if isDeltaOdd {
			delta.Add(delta, mtsn.Big.One)
		}
	}
}

func crackMsg(clients []*RSAClient, encoded []*big.Int) (*big.Int, error) {
	m := new(big.Int)
	m.Set(mtsn.Big.One)
	total := new(big.Int).Set(mtsn.Big.Zero)
	
	for i := 0; i < 3; i++ {
		mod := (*big.Int)(clients[i])
		m_i := new(big.Int)
		m_i = m_i.Mul(
			(*big.Int)(clients[(i+1) % 3]),
			(*big.Int)(clients[(i+2) % 3]),
		)
		m.Mul(m, mod)

		y_i, err := InvMod(m_i, mod)
		if (err != nil) {return nil, err}
		
		part := new(big.Int)
		part.Mul(encoded[i], m_i)
		part.Mul(part, y_i)
		total.Add(total, part)
	}

	total.Mod(total, m)
	return BinarySearchCubeRoot(total)
}

func Challenge40() {
	msg := []byte("secret")

	clients := make([]*RSAClient, 3)
	encoded := make([]*big.Int, 3)

	for i := 0; i < 3; i++ {
		rsa := NewRSA()
		clients[i] = rsa.Client()
		encoded[i] = clients[i].Encrypt(msg)
	}

	cracked, err := crackMsg(clients, encoded)

	if err != nil {
		fmt.Printf("Challenge 40: %s\n", err)
	} else {
		decoded := cracked.Bytes()
		fmt.Printf("Challenge 40: decrypted %q match? %v\n",
			decoded, bytes.Equal(msg, decoded))
	}	
}