package main

import (
	"fmt"
	//"math/big"
)

func main() {
	a := (`1. I  am  a string of one hundred and twenty eight bytes, which
        is perfect for this test here, to match this block size.`)
	fmt.Printf("a: %q, len(a): %d\n", a, len(a))
}
