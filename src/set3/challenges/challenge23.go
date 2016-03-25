package set3

import (
	"mtsn"
	"fmt"
)

func createState(previousValues []uint32) *mtsn.MersenneRNGState {
	state := new(mtsn.MersenneRNGState)

	for i, n := range previousValues {
		state.Mt[i] = mtsn.Unextract(n)
	}
	state.Index = 624
	return state
}

func Challenge23() {
	seed := uint32(42)
	state := mtsn.MersenneRNG(seed)
	first624Values := make([]uint32, 624)

	for i := 0; i < 624; i++ {
		first624Values[i] = state.Extract()
	}

	nextRandomNumber := state.Extract()
	generatedState := createState(first624Values)
	myGuess := generatedState.Extract()

	fmt.Printf("Challenge 23: My guess is %d, which matches: %v\n", myGuess, myGuess == nextRandomNumber)
}
