package main

import (
	"mtsn"
	"set6/challenges"
)

func main() {
	challenges := make(mtsn.ChallengeList)
	challenges["41"] = set6.Challenge41
	challenges["42"] = set6.Challenge42
	challenges["43"] = set6.Challenge43
	challenges["44"] = set6.Challenge44

	challenges.Run()
}
