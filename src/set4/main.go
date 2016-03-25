package main
import (
	"set4/challenges"
	"flag"
)

func main() {
	slowArgPtr := flag.Bool("slow", false, "Should run the really slow version")
	flag.Parse()

	set4.Challenge25()
	set4.Challenge26()
	set4.Challenge27()
	set4.Challenge28()
	set4.Challenge29()
	set4.Challenge30()

	if *slowArgPtr {
		set4.Challenge31()
		set4.Challenge32()
	}
}