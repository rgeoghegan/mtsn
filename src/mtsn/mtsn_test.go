package mtsn

import (
	"testing"
	"strconv"
	"bytes"
	"math"
)

func TestPadPkcs7(t *testing.T) {
	exampleString := []byte("YELLOW SUBMARINE");
	padded := PadPkcs7(exampleString);

	if (! bytes.Equal(padded, []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"))) {
		t.Log("Padded string wrong:", strconv.Quote(string(padded)))
		t.Fail()
	}

	unpadded, err := StripPkcs7(padded)
	if (err != nil) || (! bytes.Equal(unpadded, exampleString)) {
		t.Log("Unpadded string wrong:", strconv.Quote(string(unpadded)))
		t.Fail()
	}

	unpadded, err = StripPkcs7(padded[:30])
	if (err == nil) {
		t.Log("Unpadded string with errror wrong:", strconv.Quote(string(unpadded)))
		t.Fail()	
	}
}

func TestScoreAlphabet(t *testing.T) {
	score := ScoreAlphabet("abcdefghijklmnopqrstuvwxyz")
	if math.Abs(score - 0.204889093826955) > 0.0000001 {
		t.Errorf("Got score of %f\n", score)
	}
}	

func TestECBMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	text := []byte("\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8\x8d*l7\xb7-\x0c\xf4\xc2,4J\xecAB\xd0\x0c\xe50\xdd1\xb8\xc20?\xefzu\x03[\xd0K<E\xce\r\xb9:k\x8f(1\xb0\x18\xe80\xd9\xb2\xe2\xdbs")
	cleartext := []byte("I'm back and I'm ringin' the bell \nA rockin' on the mike while t")
	decrypted, err := DecryptAesEbc(key, text)

	if (err != nil) {
		t.Fatal("Error decrypting:", err)
	}

	if (! bytes.Equal(cleartext, decrypted)) {
		t.Errorf("Decrypted cleartext as %q", decrypted)
	}

	cleartext = PadPkcs7([]byte("Hello world, here I am again."))
	encrypted, err := EncryptAesEbc(key, cleartext)

	if err != nil {
		t.Error("Error encrypting:", err)
	}
	decrypted, err = DecryptAesEbc(key, encrypted)

	if (! bytes.Equal(cleartext, decrypted)) {
		t.Errorf("Decrypted cleartext as %q", decrypted)
	}
}

func TestCtrStream(t *testing.T) {
	nonce := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")
	key := []byte("YELLOW SUBMARINE")
	expected := make([]byte, 16)

	stream := ctrStream(nonce, key, 0)
	decoded, err := DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected, nonce)
	copy(expected[8:16], []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}

	stream = ctrStream(nonce, key, 1)
	decoded, err = DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected[8:16], []byte("\x01\x00\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}

	stream = ctrStream(nonce, key, 257)
	decoded, err = DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected[8:16], []byte("\x01\x01\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}
}

