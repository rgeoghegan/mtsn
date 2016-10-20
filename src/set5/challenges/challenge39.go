package set5

import (
	"bytes"
	"fmt"
	"mtsn"
)

func Challenge39() {
	rsa := mtsn.NewRSA()
	client := rsa.Client()
	msg := []byte("hello")

	encrypted := client.Encrypt(msg)
	decrypted := rsa.Decrypt(encrypted)

	fmt.Printf("Challenge 39: decrypted %q match? %v\n",
		decrypted, bytes.Equal(msg, decrypted))
}
