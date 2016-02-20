package mtsn

import (
	"bytes"
	"errors"
	"crypto/rand"
    "encoding/base64"
    "strings"
    "math"
    "sort"
    "math/big"
    "fmt"
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

var LetterFrequencies = map[string]float64 {
	"z": 0.0019, "j": 0.0023, "k": 0.0038, "x": 0.0050, "q": 0.0080, "v": 0.0084,
	"w": 0.0096, "b": 0.0130, "p": 0.0161, "y": 0.0168, "f": 0.0183, "g": 0.0206,
	"punc": 0.0229, "u": 0.0233, "m": 0.0248, "d": 0.0260, "c": 0.0310, "h": 0.0348,
	"l": 0.0405, "o": 0.0463, "r": 0.0524, "n": 0.0554, "s": 0.0558, "i": 0.0585,
	"a": 0.0646, "t": 0.0677, "e": 0.1101, " ": 0.1514, "other": 0.0,
}

var punctuation string = "!\"$&',.:;?"

func ScoreAlphabet(alphabet string) float64 {
	/**
	 * Given a text of letters (say an attempt at decoding), will return a
	 * score that can be compared to other alphabets. Lower is better.
	 */
	counts := make(map[string]int)

	for k := range LetterFrequencies {
		counts[k] = 0
	}

	for i := 0; i < len(alphabet); i++ {
		char := strings.ToLower(alphabet[i:i+1])
		if strings.Contains(punctuation, char) {
			counts["punc"] += 1
		} else {
			prev, exists := counts[char]
			if (exists) {
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
    score float64
}

type solutionScore []solution

func (a solutionScore) Len() int {return len(a)}
func (a solutionScore) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a solutionScore) Less(i, j int) bool { return a[i].score < a[j].score }

func SortedSolutions(text []byte) []byte {
	/* Xor's the text with all possible byte values, scores each byte value
	and returns them in order. */

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

func XorBytes(seqA []byte, seqB []byte) []byte {
	/* Returns the shortest of the two sequences xor'd with the other. */
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

func RandomNumber(start int, end int) int{
	delta := end - start

	index, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
    if (err != nil) {panic(err)}
    return int(index.Int64()) + start
}

func Escape(input []byte) []byte {
	res := bytes.Replace(input, []byte("\\"), []byte("\\\\"), -1)
	res = bytes.Replace(res, []byte(";"), []byte("\\;"), -1)
	res = bytes.Replace(res, []byte("="), []byte("\\="), -1)
	return res
}

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
			escaped = ! escaped
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

func ParseAdmin(params string) bool {
	parsed, err := ParseParamString(params)
	if (err != nil) { 
		return false
	}

	value, found := parsed["admin"]
	if ! found {
		return false
	}

	return value == "true" 
}