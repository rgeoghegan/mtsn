package set4

import (
    "mtsn"
    "fmt"
    "bytes"
)

var prefix []byte = []byte("comment1=cooking%20MCs;userdata=")
var postfix []byte = []byte(";comment2=%20like%20a%20pound%20of%20bacon")

type Oracle struct {
    key []byte
    nonce []byte
}

func (o *Oracle) encrypt(userdata []byte) []byte {
    var params bytes.Buffer
    params.Write(prefix)
    params.Write(mtsn.Escape(userdata))
    params.Write(postfix)

    return mtsn.CtrCoding(o.nonce, o.key, params.Bytes())
}

func (o *Oracle) check(payload []byte) bool {
    decoded := mtsn.CtrCoding(o.nonce, o.key, payload)
    return mtsn.ParseAdmin(string(decoded))
}

func createOracle() *Oracle {
    oracle := new(Oracle)
    oracle.key = mtsn.GenerateRandomKey()
    oracle.nonce = mtsn.GenerateRandomKey()[0:8]

    return oracle
}

func fixPayload(oracle *Oracle, payload []byte) error {
    sepOffset := len(prefix)
    equalOffset := sepOffset + 6
    payload[sepOffset]++

    for i := uint8(0); i < 255; i++ {
        payload[equalOffset] = i
        if oracle.check(payload) {
            return nil
        }
    }
    return fmt.Errorf("Cannot find trick byte :(")
}

func Challenge26() {
    oracle := createOracle()
    payload := []byte(";admi=true")
    encrypted := oracle.encrypt(payload)

    err := fixPayload(oracle, encrypted)
    if err != nil {panic(err)}
    fmt.Printf("Challenge 26: Am admin? %v\n", oracle.check(encrypted))
}
