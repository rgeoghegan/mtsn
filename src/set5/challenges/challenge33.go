package set5

import (
	"fmt"
)

func Challenge33() {
	a := NewDiffieHellman(DFConstants.P, DFConstants.G)
	b := NewDiffieHellman(DFConstants.P, DFConstants.G)

	key_a := a.SessionKey(b.MyPublic)
	key_b := b.SessionKey(a.MyPublic)

	fmt.Printf(
		"Challenge 33: Does session key A (%s...) match session key B (%s...)? %v\n",
		key_a.String()[0:6],
		key_b.String()[0:6],
		key_a.Cmp(key_b) == 0,
	)
}