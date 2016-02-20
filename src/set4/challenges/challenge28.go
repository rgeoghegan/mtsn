package set4

import (
	"mtsn"
	"fmt"
)

func TrySha1s() error {
	key := mtsn.GenerateRandomKey()
	origtext := []byte("hello world")
	digest := mtsn.Sha1Mac(key, origtext)

	if ! mtsn.VerifySha1Mac(key, origtext, digest) {
		return fmt.Errorf("Digest for '%q' did not work", origtext)
	}

	text := []byte("Hello world")
	if mtsn.VerifySha1Mac(key, text, digest) {
		return fmt.Errorf("Digest for '%q' did work!", text)
	}

	if mtsn.VerifySha1Mac(mtsn.GenerateRandomKey(), origtext, digest) {
		return fmt.Errorf("Digest for '%q' with random key did work!", origtext)
	}

	return nil
}

func Challenge28() {
	err := TrySha1s()
	if (err != nil) {panic(err)}
	fmt.Printf("Challenge 28: All good!\n")
}
