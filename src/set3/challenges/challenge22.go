package set3

import (
	"time"
	"mtsn"
	"fmt"
	"errors"
)

/*
 * Instead of waiting for this step, simply make it a noop
 */
var actuallyWait bool = false

func randomWait() {
	if ! actuallyWait {
		return;
	}

	pause := mtsn.RandomNumber(40, 100)
	time.Sleep(time.Duration(pause) * time.Second)
}

func findSeed(randomNumber uint32) (uint32, error) {
	currentTime := uint32(time.Now().Unix()) + 5
	for i := (currentTime - 210); i < currentTime; i++ {
		state := mtsn.Generator(i)
		if (state.Extract() == randomNumber) {
			return i, nil
		}
	}
	return 0, errors.New("Can't find seed :(")
}

func Challenge22() {
	randomWait()
	seed := uint32(time.Now().Unix())
	state := mtsn.Generator(uint32(seed))
	randomNumber := state.Extract()
	randomWait()

	guess, err := findSeed(randomNumber)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("My guess of seed being %d is %v\n", guess, guess == seed)
	}
}

