package mtsn

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"errors"
	"encoding/binary"
)


// EncryptAesEbc will encrypt inStr using key to build an AES ebc
// cipher.
//
// The key must be 16 bytes long, and inStr must match the block size.
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

// DecryptAesCbc will decrypt inStr using key to build an AES ebc
// cipher.
//
// The key must be 16 bytes long, and inStr must match the block size.
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

// EncryptAesCbc will encrypt inStr using key and iv to build an AES cbc
// cipher.
//
// Both iv and key must be 16 bytes long, and inStr must match the block size.
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

// DecryptAesCbc will decrypt inStr using key and iv to build an AES cbc
// cipher.
//
// Both iv and key must be 16 bytes long, and inStr must match the block size.
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

// CtrStream will use key and nonce to produce a ctr stream of bytes count
// bytes long.
//
// key must be 16 bytes long, nonce must be 8 bytes long.
func CtrStream(nonce []byte, key []byte, count uint16) []byte {
	output := make([]byte, 16)
	copy(output, nonce)
	binary.LittleEndian.PutUint16(output[8:16], count)

	encoded, err := EncryptAesEbc(key, output)
	if (err != nil) {panic(err)}

	return encoded
}

//CtrCoding will use key and nonce to produce a ctr-encoded (or decoded)
//version of text.
//
// key must be 16 bytes long, nonce must be 8 bytes long.
func CtrCoding(nonce []byte, key []byte, text []byte) []byte {
	/* Given
	*
    *  nonce: 8 bytes
    *  key: 16 bytes
    *  text: as long as you want
    *
    *  produces the ctr-encoded/decoded version of the text
    */
    output := make([]byte, len(text))
    output_i := 0

    for block_i := 0;; block_i++ {
    	block := CtrStream(nonce, key, uint16(block_i))
    	for i := 0; i < len(block); i++ {
    		output[output_i] = text[output_i] ^ block[i]
    		output_i++

    		if (output_i >= len(output)) {
    			return output
    		}
    	}
    }
}
