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

	stream := CtrStream(nonce, key, 0)
	decoded, err := DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected, nonce)
	copy(expected[8:16], []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}

	stream = CtrStream(nonce, key, 1)
	decoded, err = DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected[8:16], []byte("\x01\x00\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}

	stream = CtrStream(nonce, key, 257)
	decoded, err = DecryptAesEbc(key, stream)
	if (err != nil) {
		t.Fatalf("Error in decrtypting: %s", err)
	}

	copy(expected[8:16], []byte("\x01\x01\x00\x00\x00\x00\x00\x00"))
	if ! bytes.Equal(decoded, expected) {
		t.Errorf("Decoded is equal to %q", decoded)
	}
}

func TestGenerator(t *testing.T) {
	state := Generator(42)
	passes := state.Index == 624
	passes = passes && state.Mt[0] == 42
	passes = passes && state.Mt[1] == 0xb93c8a93
	passes = passes && state.Mt[2] == 0x71014437
	passes = passes && state.Mt[state.Index - 1] == 0x197b52a

	if ! passes {
		t.Errorf("Index %v, state values are 0x%x, 0x%x, 0x%x and 0x%x",
			state.Index, state.Mt[0], state.Mt[1], state.Mt[2], state.Mt[state.Index - 1])
	}
}

func TestTwist(t *testing.T) {
	state := Generator(42)
	state.Twist()
	passes := state.Index == 0
	passes = passes && 0x2b26e943 == state.Mt[0]
	passes = passes && 0xf3ac425f == state.Mt[n - 1];

	if ! passes {
		t.Errorf("Index %v, state values are [0]: 0x%x, [%d]: 0x%x",
			state.Index, state.Mt[0], n, state.Mt[n-1])
	}
}

func TestExtract(t *testing.T) {
	state := Generator(42)
	
	value := state.Extract()
	if (value != 0x5fe1dc66) {
		t.Errorf("First extracted number is 0x%x", value)
	}

	value = state.Extract()
	if (value != 0xcbea3db3) {
		t.Errorf("Second extracted number is 0x%x", value)
	}

	for i := 0; i < 9; i++ {
		state.Extract()
	}

	value = state.Extract()
	if (value != 0x1997f4d6) {
		t.Errorf("Eleventh extracted number is 0x%x", value)
	}
}

func TestEscape(t *testing.T) {
	var expectations []string = []string{
		";\\=", "\\;\\\\\\=",
	}

	for i := 0; i < len(expectations); i += 2 {
		result := Escape([]byte(expectations[i]))
		if ! bytes.Equal(result, []byte(expectations[i+1])) {
			t.Errorf("Expected %v, got %q instead", expectations[i+1], result)
		}
	}
}

func TestParseParamString(t *testing.T) {
	parsed, err := ParseParamString("a=b;c=d")
	if err != nil {panic(err)}
	if parsed["a"] != "b" || parsed["c"] != "d" || len(parsed) != 2 {
		t.Errorf(
			"Got %d keys in parsed, a: %v, c: %v", len(parsed), parsed["a"], parsed["c"],
		)
	}

	parsed, err = ParseParamString("a=b\\;;c=d")
	if err != nil {panic(err)}
	if "b;" != parsed["a"] {
		t.Errorf("Got %v for key a", parsed["a"])
	}
}

func TestParseAdmin(t *testing.T) {
	testString := "a=b;admin=true;rory=cool"
	if ! ParseAdmin(testString) {
		t.Errorf("String %v is _not_ admin", testString)
	}

	testString = "a=b;admin=false;rory=cool"
	if ParseAdmin(testString) {
		t.Errorf("String %v _is_ admin", testString)
	}

	testString = "a=b;admn=true;rory=cool"
	if ParseAdmin(testString) {
		t.Errorf("String %v _is_ admin", testString)
	}

	testString = "a=b;admin==true;rory=cool"
	if ParseAdmin(testString) {
		t.Errorf("String %v _is_ admin", testString)
	}
}
