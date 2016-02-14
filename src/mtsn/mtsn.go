package mtsn

import (
	"bytes"
	"errors"
	"crypto/rand"
    "encoding/base64"
)

func DecodeBase64(indata string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(indata)
	// Not really interested in handling bad Base64 data, so just panic.
	if (err != nil) {panic(err)}
	return decoded
}

func PadPkcs7(inStr []byte) []byte {
	length := len(inStr)
	extra := 16 - (length % 16)
	padded := bytes.NewBuffer(inStr)

	for i := 0; i < extra; i++ {
		padded.WriteByte(byte(extra))
	}
	return padded.Bytes()
}

func StripPkcs7(inStr []byte) ([]byte, error) {
	length := len(inStr)
	padNum := int(inStr[length-1])

	if (padNum == 0) {
		return nil, errors.New("Padding of 0 invalid")
	}
	if (padNum > 16) {
		return nil, errors.New("Padding value too high")
	}

	for i := 2; i < (padNum + 1); i++ {
		if (inStr[length-i] != uint8(padNum)) {
			return nil, errors.New("Padding not complete")
		}
	}
	return inStr[0:length-padNum], nil
}

func GenerateRandomKey() []byte {
	output := make([]byte, 16)
	_, err := rand.Read(output)

	if err != nil {
		panic(err)
	}
	return output
}
