package mtsn

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"errors"
)

func EncryptAesEbc(key []byte, inStr []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {return nil, err}

	if ((len(inStr) % cipher.BlockSize()) != 0) {
		msg := fmt.Sprintf("Input string must be a multiple of %d", cipher.BlockSize())
		errors.New(msg)
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
