package mtsn

import (
	"testing"
	"strconv"
	"bytes"
)

func TestSplitStringIntoList(t *testing.T) {
    parts := SplitStringIntoList("abcdef", 3);

    if (parts[0] != "abc") {
    	t.Log("First part is", parts[0])
    	t.Fail()
    }
    if (parts[1] != "def") {
    	t.Log("Second part is %s", parts[1])
    	t.Fail()
    }

    parts = SplitStringIntoList("abcde", 3)
    if (parts[0] != "abc") {
    	t.Log("First part is", parts[0])
    	t.Fail()
    }
    if (parts[1] != "de") {
    	t.Log("Second part is", parts[1])
    	t.Fail()
    }
}

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

func TestECBMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	text := []byte("\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8\x8d*l7\xb7-\x0c\xf4\xc2,4J\xecAB\xd0\x0c\xe50\xdd1\xb8\xc20?\xefzu\x03[\xd0K<E\xce\r\xb9:k\x8f(1\xb0\x18\xe80\xd9\xb2\xe2\xdbs")
	cleartext := []byte("I'm back and I'm ringin' the bell \nA rockin' on the mike while t")
	decrypted, err := DecryptAesEbc(key, text)

	if (err != nil) {
		t.Log("Error decrypting:", err)
		t.FailNow()
	}

	if (! bytes.Equal(cleartext, decrypted)) {
		t.Log("Decrypted cleartext as ", strconv.Quote(string(decrypted)))
		t.Fail()
	}

	cleartext = PadPkcs7([]byte("Hello world, here I am again."))
	encrypted, err := EncryptAesEbc(key, cleartext)

	if err != nil {
		t.Log("Error encrypting:", err)
		t.FailNow()
	}
	decrypted, err = DecryptAesEbc(key, encrypted)

	if (! bytes.Equal(cleartext, decrypted)) {
		t.Log("Decrypted cleartext as ", strconv.Quote(string(decrypted)))
		t.Fail()
	}
}
