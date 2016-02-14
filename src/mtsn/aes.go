package mtsn

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"errors"
	"encoding/binary"
)

func EncryptAesEbc(key []byte, inStr []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {return nil, err}

	if ((len(inStr) % cipher.BlockSize()) != 0) {
		msg := fmt.Sprintf("Input string must be a multiple of %d", cipher.BlockSize())
		return nil, errors.New(msg)
	}

	output := make([]byte, len(inStr))

	for i := 0; i < len(inStr); i += cipher.BlockSize() {
		cipher.Encrypt(
			output[i:i+cipher.BlockSize()], inStr[i:i+cipher.BlockSize()])
	}

	return output, nil
}

func DecryptAesEbc(key []byte, inStr []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {return nil, err}

	if ((len(inStr) % cipher.BlockSize()) != 0) {
		msg := fmt.Sprintf("Input string must be a multiple of %d", cipher.BlockSize())
		errors.New(msg)
	}

	output := make([]byte, len(inStr))

	for i := 0; i < len(inStr); i += cipher.BlockSize() {
		cipher.Decrypt(
			output[i:i+cipher.BlockSize()], inStr[i:i+cipher.BlockSize()])
	}

	return output, nil
}

func EncryptAesCbc(key []byte, iv []byte, inStr []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {return nil, err}

	if ((len(inStr) % block.BlockSize()) != 0) {
		msg := fmt.Sprintf("Input string must be a multiple of %d", block.BlockSize())
		return nil, errors.New(msg)
	}

	output := make([]byte, len(inStr))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(output, inStr)

	return output, nil
}

func DecryptAesCbc(key []byte, iv []byte, inStr []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {return nil, err}

	if ((len(inStr) % block.BlockSize()) != 0) {
		msg := fmt.Sprintf("Input string must be a multiple of %d", block.BlockSize())
		return nil, errors.New(msg)
	}

	output := make([]byte, len(inStr))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(output, inStr)

	return output, nil
}

func ctrStream(nonce []byte, key []byte, count uint16) []byte {
	output := make([]byte, 16)
	copy(output, nonce)
	binary.LittleEndian.PutUint16(output[8:16], count)

	encoded, err := EncryptAesEbc(key, output)
	if (err != nil) {panic(err)}

	return encoded
}

func CtrCoding(nonce []byte, key []byte, text []byte) []byte {
	/* Given
	*
    *  nonce: 8 bytes
    *  key: 16 bytes
    *  text: as long as you want
    *
    *  produces the ctr-encoded version of the text
    */
    output := make([]byte, len(text))
    output_i := 0

    for block_i := 0;; block_i++ {
    	block := ctrStream(nonce, key, uint16(block_i))
    	for i := 0; i < len(block); i++ {
    		output[output_i] = text[output_i] ^ block[i]
    		output_i++

    		if (output_i >= len(output)) {
    			return output
    		}
    	}
    }
}
