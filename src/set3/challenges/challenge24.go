package set3

import (
    "mtsn"
    "bytes"
    "fmt"
    "time"
)

const (
    MAX_SEED_SIZE int = 0xffff
)

var TOKEN []byte = []byte("password reset token")

func getByte(n uint32, x uint32) byte {
    return byte((n >> (x * 8)) & 0xff)
}

func ctrMt19937Encode(key uint32, text []byte) []byte {
    /* Given
     *
     *  key: 32 bit number
     *  text: as long as you want
     *
     * produces the ctr-encoded version of the text using a Mersenne rng
     */
    state := mtsn.Generator(key)
    strLen := uint32(len(text))
    output := make([]byte, strLen)

    for i := uint32(0); i < strLen; i += 4 {
        block := state.Extract()
        for j := uint32(0); j < 4 && (j + i) < strLen; j++ {
            output[j + i] = getByte(block, j)
        }
    }

    return mtsn.XorBytes(text, output)
}

func decryptCtrAaaa(ciphertext []byte) (int, error) {
    padded := bytes.Repeat([]byte("A"), len(ciphertext))
    interestingCiphertext := ciphertext[len(ciphertext) - 14:len(ciphertext)]

    for i := 0; i <= MAX_SEED_SIZE; i++ {
        encoded := ctrMt19937Encode(uint32(i), padded)
        if bytes.Equal(encoded[len(ciphertext) - 14:len(ciphertext)], interestingCiphertext) {
            return i, nil
        }
    }
    return 0, fmt.Errorf("Could not find matching seed :(")
}

func encryptToken() []byte {
    key := uint32(time.Now().Unix())
    return ctrMt19937Encode(key, TOKEN)
}

func assertEncryptedToken(token []byte) bool {
    currentTime := uint32(time.Now().Unix())
    for i := currentTime - 20; i <= currentTime; i++ {
        decoded := ctrMt19937Encode(i, token)
        if bytes.Equal(decoded, TOKEN) {
            return true
        }
    }
    return false
}

func Challenge24() {
    key := uint32(mtsn.RandomNumber(0, MAX_SEED_SIZE))
    cleartextSize := mtsn.RandomNumber(0, 10)
    cleartext := make([]byte, cleartextSize + 14)

    for i := 0; i < cleartextSize; i++ {
        cleartext[i] = uint8(mtsn.RandomNumber(0, 256))
    }
    for i := 0; i < 14; i++ {
        cleartext[i + cleartextSize] = 'A'
    }

    ciphertext := ctrMt19937Encode(key, cleartext)

    // We can encrypt and decrypt
    decoded := ctrMt19937Encode(key, ciphertext)
    if ! bytes.Equal(decoded, cleartext) {
        panic(fmt.Errorf("Decoded this from ciphertext: %q", decoded))
    }

    // Crack the seed
    cracked, err := decryptCtrAaaa(ciphertext)
    if err != nil {
        panic(err)
    }
    if uint32(cracked) != key {
        panic(fmt.Errorf("Got key 0x%x instead of 0x%x", cracked, key))
    }

    // Now play around with a token
    token := encryptToken()
    fmt.Printf("Challenge 24: Found key 0x%x, and is token: %v\n", cracked, assertEncryptedToken(token))

}
