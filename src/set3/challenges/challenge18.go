package set3

import (
	"mtsn"
	"fmt"
)

func Challenge18() {
	encryptedBase64 := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	nonce := make([]byte, 8)
	key := []byte("YELLOW SUBMARINE")

	encrypted := mtsn.DecodeBase64(encryptedBase64)

	fmt.Printf("Challenge 18: Decrypted %q\n", mtsn.CtrCoding(nonce, key, encrypted))
}
