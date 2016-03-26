package set5

import (
	"fmt"
)

func Challenge33() {
	a := NewDiffieHellman()
	b := NewDiffieHellman()
	a.Exchange(b)

	key_a := a.SessionKey()
	key_b := b.SessionKey()

	fmt.Printf(
		"Challenge 32: Does session key A (%s...) match session key B (%s...)? %v\n",
		key_a.String()[0:6],
		key_b.String()[0:6],
		key_a.Cmp(key_b) == 0,
	)
}