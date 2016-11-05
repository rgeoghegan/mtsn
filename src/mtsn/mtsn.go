// The mtsn package contains utility code that is shared among the challenges.
package mtsn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"
)

// DecodeBase64 will decode the given Base64 encoded string into a []byte.
func DecodeBase64(indata string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(indata)
	// Not really interested in handling bad Base64 data, so just panic.
	if err != nil {
		panic(err)
	}
	return decoded
}

// PadPkcs7 will pad the given []byte using Pkcs #7.
func PadPkcs7(inStr []byte) []byte {
	length := len(inStr)
	extra := 16 - (length % 16)
	padded := bytes.NewBuffer(inStr)

	for i := 0; i < extra; i++ {
		padded.WriteByte(byte(extra))
	}
	return padded.Bytes()
}

// StripPkcs7 will strip the padding as done by PadPkcs7.
func StripPkcs7(inStr []byte) ([]byte, error) {
	length := len(inStr)
	padNum := int(inStr[length-1])

	if padNum == 0 {
		return nil, errors.New("Padding of 0 invalid")
	}
	if padNum > 16 {
		return nil, errors.New("Padding value too high")
	}

	for i := 2; i < (padNum + 1); i++ {
		if inStr[length-i] != uint8(padNum) {
			return nil, errors.New("Padding not complete")
		}
	}
	return inStr[0 : length-padNum], nil
}

// GenerateRandomKey will generate a random sequece of 16 bytes, which can be
// used as a key in different ciphers, etc.
func GenerateRandomKey() []byte {
	output := make([]byte, 16)
	_, err := rand.Read(output)

	if err != nil {
		panic(err)
	}
	return output
}

var LetterFrequencies = map[string]float64{
	"z": 0.0019, "j": 0.0023, "k": 0.0038, "x": 0.0050, "q": 0.0080, "v": 0.0084,
	"w": 0.0096, "b": 0.0130, "p": 0.0161, "y": 0.0168, "f": 0.0183, "g": 0.0206,
	"punc": 0.0229, "u": 0.0233, "m": 0.0248, "d": 0.0260, "c": 0.0310, "h": 0.0348,
	"l": 0.0405, "o": 0.0463, "r": 0.0524, "n": 0.0554, "s": 0.0558, "i": 0.0585,
	"a": 0.0646, "t": 0.0677, "e": 0.1101, " ": 0.1514, "other": 0.0,
}

var punctuation string = "!\"$&',.:;?"

// ScoreAlphabet, given a text of letters (say an attempt at decoding), will return a
// score that can be compared to other alphabets. Lower is better.
func ScoreAlphabet(alphabet string) float64 {
	counts := make(map[string]int)

	for k := range LetterFrequencies {
		counts[k] = 0
	}

	for i := 0; i < len(alphabet); i++ {
		char := strings.ToLower(alphabet[i : i+1])
		if strings.Contains(punctuation, char) {
			counts["punc"] += 1
		} else {
			prev, exists := counts[char]
			if exists {
				counts[char] = prev + 1
			} else {
				counts["other"] = counts["other"] + 1
			}
		}
	}

	totalDiffence := 0.0
	for k, v := range counts {
		diff := (float64(v) / float64(len(alphabet))) - LetterFrequencies[k]
		totalDiffence += diff * diff
	}
	totalDiffence = math.Sqrt(totalDiffence)
	return totalDiffence
}

type solution struct {
	cipher uint8
	score  float64
}

type solutionScore []solution

func (a solutionScore) Len() int           { return len(a) }
func (a solutionScore) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a solutionScore) Less(i, j int) bool { return a[i].score < a[j].score }

// SortedSolutions will xor text with all possible byte values, score each
// xor'd text using ScoreAlphabet, and return the xor'ing bytes in order of
// their score.
func SortedSolutions(text []byte) []byte {
	var solutions solutionScore = make(solutionScore, 256)
	for i := 0; i < 256; i++ {
		solutions[i].cipher = byte(i)
		evaluation := make([]byte, len(text))

		for j := 0; j < len(text); j++ {
			evaluation[j] = text[j] ^ solutions[i].cipher
		}
		solutions[i].score = ScoreAlphabet(string(evaluation))
	}
	sort.Sort(solutions)

	output := make([]byte, 256)
	for i, n := range solutions {
		output[i] = n.cipher
	}
	return output
}

// XorBytes returns the shortest of the two sequences xor'd with the other.
func XorBytes(seqA []byte, seqB []byte) []byte {
	minLength := len(seqA)
	if len(seqB) < minLength {
		minLength = len(seqB)
	}

	output := make([]byte, minLength)
	for i := 0; i < minLength; i++ {
		output[i] = seqA[i] ^ seqB[i]
	}
	return output
}

// RandomNumber generates a random number from [start,end), so the range
// including start but *not* including end.
func RandomNumber(start int, end int) int {
	delta := end - start

	index, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		panic(err)
	}
	return int(index.Int64()) + start
}

// Escape will escape '\', ';' and '=' with a '\' in a []byte
func Escape(input []byte) []byte {
	res := bytes.Replace(input, []byte("\\"), []byte("\\\\"), -1)
	res = bytes.Replace(res, []byte(";"), []byte("\\;"), -1)
	res = bytes.Replace(res, []byte("="), []byte("\\="), -1)
	return res
}

// ParseParamString will take a string and parse it as key=value pairs joined
// by ;. Either =, l, or \ can be escaped by adding another \ in front of it,
// as per the Escape function.
func ParseParamString(params string) (map[string]string, error) {
	escaped := false
	results := make(map[string]string)

	if len(params) == 0 {
		return results, nil
	}

	key := new(bytes.Buffer)
	value := new(bytes.Buffer)

	for i, c := range params {
		if c == ';' || c == '=' {
			if i == 0 {
				return nil, fmt.Errorf("Params start with %v", c)
			}

			if escaped {
				value.WriteRune(c)
				escaped = false
				continue
			}

			if c == '=' {
				if key.Len() > 0 {
					return nil, fmt.Errorf("Double '=' at pos %v", i)
				}
				if value.Len() == 0 {
					return nil, fmt.Errorf("Zero length key at pos %v", i)
				}

				key = value
				value = new(bytes.Buffer)
			} else {
				if key.Len() == 0 {
					return nil, fmt.Errorf("Next block starts without '=' at pos %v", i)
				}
				results[key.String()] = value.String()
				key = new(bytes.Buffer)
				value = new(bytes.Buffer)
			}
		} else if c == '\\' {
			if escaped {
				value.WriteRune(c)
			}
			escaped = !escaped
		} else {
			value.WriteRune(c)
			escaped = false
		}
	}

	if escaped {
		return nil, fmt.Errorf("Params end with \\")
	}
	if key.Len() == 0 || value.Len() == 0 {
		return nil, fmt.Errorf("Last block is incomplete.")
	}
	results[key.String()] = value.String()

	return results, nil
}

// ParseAdmin will parse params as per ParseParamString, look for the key
// 'admin' and make sure it's value is 'true'
func ParseAdmin(params string) bool {
	parsed, err := ParseParamString(params)
	if err != nil {
		return false
	}

	value, found := parsed["admin"]
	if !found {
		return false
	}

	return value == "true"
}

// GetByte extracts the given offset byte from int n.
func GetByte(n int, offset uint) byte {
	return byte(n >> (8 * offset))
}

// Function to print out a big int with scientific notation, i.e. 1 -> 1e0
func FmtBigInt(n *big.Int) string {
	toStr := n.String()
	if len(toStr) < 15 {
		return toStr
	}

	return fmt.Sprintf(
		"%c.%se%d",
		toStr[0],
		toStr[1:10],
		len(toStr)-1,
	)
}

// Some small numbers as *big.Int. Please do not modify them, or else things
// will fall appart.
var Big = struct {
	Zero  *big.Int
	One   *big.Int
	Two   *big.Int
	Three *big.Int
}{
	big.NewInt(int64(0)),
	big.NewInt(int64(1)),
	big.NewInt(int64(2)),
	big.NewInt(int64(3)),
}

func HexBigInt(number string) *big.Int {
	replacer := strings.NewReplacer("\t", "", " ", "", "\n", "", "\r", "")
	clean := replacer.Replace(number)
	output := new(big.Int)

	count, err := fmt.Sscanf(clean, "%x", output)
	if err != nil {
		panic(err)
	}
	if count != 1 {
		panic(fmt.Errorf("Expecting one number, got %d instead", count))
	}
	return output
}

type ChallengeList map[string](func())

func (cl ChallengeList) RunAll() {
	for _, fn := range cl {
		fn()
	}
}

func (cl ChallengeList) Usage() {
	var challenges []string

	for challenge := range cl {
		challenges = append(challenges, challenge)
	}

	fmt.Fprintf(os.Stderr, "USAGE: %s [%s]\n", os.Args[0],
		strings.Join(challenges, ","))
}

func (cl ChallengeList) Run() {
	if len(os.Args) < 2 {
		cl.RunAll()
		return
	}

	for _, challengeName := range os.Args[1:len(os.Args)] {
		if challenge, ok := cl[challengeName]; ok {
			challenge()
		} else {
			fmt.Fprintf(os.Stderr, "arg %q is not a valid challenge name\n", challengeName)
			cl.Usage()
			os.Exit(1)
		}
	}
}
