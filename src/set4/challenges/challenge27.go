package set4

import (
    "bytes"
    "fmt"
    "mtsn"
)

var payload []byte = []byte("comment1=cooking%20MCs;userdata=stuff;comment2=%20like%20a%20pou")

func checkForAscii(str []byte) bool {
    for _, c := range str {
        if c > 127 {
            return false
        }
    }
    return true
}

type Error struct {
    decrypted []byte
}

func (e *Error) Error() string {
    return fmt.Sprintf("Non ascii bytes in '%q'", e.decrypted)
}

type Oracle27 struct {
    key []byte
    encrypted []byte
}

func createOracle27() *Oracle27 {
    res := new(Oracle27)
    res.key = mtsn.GenerateRandomKey()
    
    var err error
    res.encrypted, err = mtsn.EncryptAesCbc(res.key, res.key, payload)
    if err != nil {panic(err)}

    return res
}

func (o *Oracle27) Decode(encrypted []byte) *Error {
    decrypted, err := mtsn.DecryptAesCbc(o.key, o.key, encrypted)
    if err != nil {panic(err)}

    if checkForAscii(decrypted) {
        return nil
    }

    myerr := new(Error)
    myerr.decrypted = decrypted
    return myerr
}

func Challenge27() {
    oracle := createOracle27()
    attack := bytes.Repeat([]byte("\x00"), 48)
    copy(attack, oracle.encrypted[0:16])
    copy(attack[32:48], oracle.encrypted[0:16])

    err := oracle.Decode(attack)

    if err == nil {
        fmt.Printf("Failed :(\n")
    } else {
        text := err.decrypted
        decodedKey := mtsn.XorBytes(text[0:16], text[32:48])
        fmt.Printf("Challenge 27: Decoded key %q? %v\n", decodedKey, bytes.Equal(decodedKey, oracle.key))
    }

}
