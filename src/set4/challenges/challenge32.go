package set4

import (
	"mtsn"
	"fmt"
	"time"
	"sort"
	"sha1hacks"
	"github.com/mitsuse/progress-go"
)

const TIMING_TRIES int = 10
const LOOP_TRIES int = 3
const BAR_WIDTH int = 106

// Timing, a pair of byte guessed with the duration of the hashing
type Timing struct {
	guess byte
	duration time.Duration
}


// Timings, Timing slice that implements sort.Interface
type Timings []*Timing

func (t Timings) Len() int { return len(t) }
func (t Timings) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }
func (t Timings) Less(i, j int) bool { return t[i].duration < t[j].duration }

type SignatureBreaker struct {
	verifier *HmacVerifier
	content []byte
	signature []byte
	progressBar progress.ProgressBar
}

func (s *SignatureBreaker) Byte(index int) byte {
	if index < 0 {
		panic(fmt.Errorf("Trying to find a block below 0"))
	}

	results := make(Timings, 0, 256)

	for guess := 0; guess < 256; guess++ {
		timing := new(Timing)
		timing.guess = byte(guess)
		s.signature[index] = timing.guess

		// Take TIMING_TRIES samples, keep the shortest one because that it
		// the one least affected by context switches, page swaps, etc.
		for i := 0; i < TIMING_TRIES; i++ {
			s.signature[index+1] = byte(i)
			duration := s.TimeRun()

			if ((i == 0) || (duration < timing.duration)) {
				timing.duration = duration
			}
			s.progressBar.Add(1)
		}

		results = append(results, timing)
	}

	sort.Sort(results)
	return results[255].guess
}

func (s *SignatureBreaker) TimeRun() time.Duration {
	start := time.Now()
	s.verifier.insecureCompare(s.content, s.signature)
	end := time.Now()
	return end.Sub(start)
}


func (s *SignatureBreaker) Break() {
	fmt.Printf("Starting time-based guessing\n")
	s.progressBar.Show()
	for i := 0; i < sha1hacks.Size - LOOP_TRIES; i++ {
		s.signature[i] = s.Byte(i)
	}
	s.progressBar.Close()

	loopCounter := 1
	for i := 0; i < LOOP_TRIES; i++ {
		loopCounter *= 256
	}

	s.progressBar = progress.NewSimple(loopCounter, BAR_WIDTH)
	fmt.Printf("Starting last %d bytes guessing\n", LOOP_TRIES)
	s.progressBar.Show()

	for i := 0; i < loopCounter; i++ {
		for j := 0; j < LOOP_TRIES; j++ {
			s.signature[sha1hacks.Size - LOOP_TRIES + j] = mtsn.GetByte(i, uint(j))
		}
		if s.verifier.compare(s.content, s.signature) {
			s.progressBar.Close()
			return
		}
		s.progressBar.Add(1)
	}
	s.progressBar.Close()
	panic(fmt.Errorf("Cannot pick out last %d bytes", LOOP_TRIES))
}

// NewSignatureBreaker instantiates a new SignatureBreaker object.
//
// nBytes: the number of bytes to break (for the progress bar). Should be
// equal to Sha1.Size.
func NewSignatureBreaker(verifier *HmacVerifier, content []byte,
		signature []byte, nBytes int) *SignatureBreaker {
	pbar := progress.NewSimple(nBytes * 256 * TIMING_TRIES, BAR_WIDTH)
	return &SignatureBreaker{verifier, content, signature, pbar}
}

func Challenge32() {
	key := mtsn.GenerateRandomKey()
	verifier := HmacVerifier{key, 5}
	badFile := []byte("I am a bad file which will ruin your day")
	signature := make([]byte, sha1hacks.Size)

	breaker := NewSignatureBreaker(
		&verifier, badFile, signature, sha1hacks.Size - LOOP_TRIES,
	)
	breaker.Break()

	fmt.Printf("Challenge 32: can fake signature? %v\n",
	 	verifier.compare(badFile, breaker.signature))
}