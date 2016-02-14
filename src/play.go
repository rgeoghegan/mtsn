package main
import "fmt"
//import "strconv"
// import "crypto/aes"

func blah(b []byte) {
	c := b[0:4]
	b[0] = 65
	c[0] = 97

	fmt.Printf("b: %q\n", b)
	fmt.Printf("c: %q\n", c)
}

func main() {
	a := []byte("bbbb")
	blah(a)
	fmt.Printf("a: %q\n", a)
}