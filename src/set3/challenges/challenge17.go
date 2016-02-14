package set3

import (
    "fmt"
    "crypto/rand"
    "errors"
    "math/big"
    "mtsn"
    "bytes"
)

var randomStrings [10]string = [...]string{
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

type Oracle struct {
    key []byte
    ivString []byte
    cipherText []byte
}

func createOracle() *Oracle {
    index, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomStrings))))
    if (err != nil) {panic(err)}

    cleartext := mtsn.DecodeBase64(randomStrings[index.Int64()])
    if (err != nil) {panic(err)}

    padded := mtsn.PadPkcs7([]byte(cleartext))
    oracle := &Oracle{
         mtsn.GenerateRandomKey(),
         mtsn.GenerateRandomKey(),
         nil,
    }

    cipherText, err := mtsn.EncryptAesCbc(oracle.key,
        oracle.ivString, padded)
    if err != nil {panic(err)}
    oracle.cipherText = cipherText

    return oracle
}

func (o *Oracle) Encrypt() ([]byte, []byte) {
    return o.cipherText, o.ivString
}

func (o *Oracle) Decrypt(iv []byte, ciphertext []byte) bool {
    rawtext, err := mtsn.DecryptAesCbc(o.key, iv, ciphertext)
    if (err != nil) {panic(err)}

    _, err = mtsn.StripPkcs7(rawtext)
    return err == nil
}

func findMatchingBytes(oracle *Oracle, block []byte, iv []byte, pos int64, start uint8) (uint8, error) {
    for i := int64(start); i < 256; i++ {
        iv[pos] = uint8(i)
        if oracle.Decrypt(iv, block) {
            return uint8(i), nil
        }
    }
    return 0, errors.New("Cannot find matching byte")
}

func tryPadding(oracle *Oracle, iv []byte, block []byte, padding uint8, decoded []byte) (uint8, bool) {
    pos := 16 - int64(padding)
    for i := pos; i < 16; i++ {
        iv[i] = decoded[i] ^ padding
    }

    byteValue, err := findMatchingBytes(oracle, block, iv, pos, 0)
    if (err != nil) {return 0, false}

    return byteValue, true
}

func decodeBlock(oracle *Oracle, origIv []byte, block []byte) ([]byte, error){
    decoded := make([]byte, 16)
    iv := make([]byte, 16)
    copy(iv, origIv)

    first, err := findMatchingBytes(oracle, block, iv, 15, 0)
    if (err != nil) {return nil, errors.New("Cannot fix even first last byte")}

    var padding uint8 = 2
    decoded[15] = first ^ 0x01

    second, err := findMatchingBytes(oracle, block, iv, 15, first + 1)
    if (err == nil) {
        secondByte, works := tryPadding(oracle, iv, block, 2, decoded)
        if works {
            decoded[14] = secondByte ^ 0x02
            padding = 3
        } else {
            decoded[15] = second ^ 0x01
        }
    }

    for ; padding < 17; padding++ {
        match, works := tryPadding(oracle, iv, block, padding, decoded)
        if (!works) {
            return nil, errors.New(fmt.Sprintf("Can't match byte for padding %d", padding))
        }
        decoded[16 - padding] = match ^ padding
    }

    ciphertext := make([]byte, 16)
    for i := 0; i<16; i++ {
        ciphertext[i] = decoded[i] ^ origIv[i]
    }

    return ciphertext, nil
}

func decodeText(oracle *Oracle, iv []byte, encoded []byte) []byte {
    decoded := new(bytes.Buffer)
    decoded.Grow(len(encoded))
    prev := iv
    for i := 0; i < len(encoded); i += 16 {
        block := encoded[i:i+16]
        decodedBlock, err := decodeBlock(oracle, prev, block)
        if (err != nil) {panic(err)}

        _, _ = decoded.Write(decodedBlock)
        prev = block
    }

    ret, err := mtsn.StripPkcs7(decoded.Bytes())
    if err != nil {panic(err)}
    return ret
}

func Challenge17() {
    oracle := createOracle()
    ciphertext, ivStr := oracle.Encrypt()
    decoded := decodeText(oracle, ivStr, ciphertext)

    for i := 0; i < len(randomStrings); i++ {
        str := mtsn.DecodeBase64(randomStrings[i])

        if bytes.Equal(decoded, str) {
            fmt.Println("Picked string:", i)
            return
        }
    }
    fmt.Println("Cannot match strings")
}
