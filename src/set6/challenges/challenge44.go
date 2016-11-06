package set6

import (
	"fmt"
	"math/big"
	"mtsn"
	"strings"
)

var challenge44Signatures string = `msg: Listen for me, you better listen for me now. 
s: 1267396447369736888040262262183731677867615804316
r: 1105520928110492191417703162650245113664610474875
m: a4db3de27e2db3e5ef085ced2bced91b82e0df19
msg: Listen for me, you better listen for me now. 
s: 29097472083055673620219739525237952924429516683
r: 51241962016175933742870323080382366896234169532
m: a4db3de27e2db3e5ef085ced2bced91b82e0df19
msg: When me rockin' the microphone me rock on steady, 
s: 277954141006005142760672187124679727147013405915
r: 228998983350752111397582948403934722619745721541
m: 21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4
msg: Yes a Daddy me Snow me are de article dan. 
s: 1013310051748123261520038320957902085950122277350
r: 1099349585689717635654222811555852075108857446485
m: 1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5
msg: But in a in an' a out de dance em 
s: 203941148183364719753516612269608665183595279549
r: 425320991325990345751346113277224109611205133736
m: 6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff
msg: Aye say where you come from a, 
s: 502033987625712840101435170279955665681605114553
r: 486260321619055468276539425880393574698069264007
m: 5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9
msg: People em say ya come from Jamaica, 
s: 1133410958677785175751131958546453870649059955513
r: 537050122560927032962561247064393639163940220795
m: 7d9abd18bbecdaa93650ecc4da1b9fcae911412
msg: But me born an' raised in the ghetto that I want yas to know, 
s: 559339368782867010304266546527989050544914568162
r: 826843595826780327326695197394862356805575316699
m: 88b9e184393408b133efef59fcef85576d69e249
msg: Pure black people mon is all I mon know. 
s: 1021643638653719618255840562522049391608552714967
r: 1105520928110492191417703162650245113664610474875
m: d22804c4899b522b23eda34d2137cd8cc22b9ce8
msg: Yeah me shoes a an tear up an' now me toes is a show a 
s: 506591325247687166499867321330657300306462367256
r: 51241962016175933742870323080382366896234169532
m: bc7ec371d951977cba10381da08fe934dea80314
msg: Where me a born in are de one Toronto, so 
s: 458429062067186207052865988429747640462282138703
r: 228998983350752111397582948403934722619745721541
m: d6340bfcda59b6b75b59ca634813d572de800e8f`

type DSAPayload struct {
	sig *DSASignature
	msg []byte
	m   *big.Int
}

func parseChallenge44Signatures() []*DSAPayload {
	lines := strings.Split(challenge44Signatures, "\n")
	signatures := make([]*DSAPayload, 0, len(lines)/4)

	for i := 0; i < len(lines); i += 4 {

		rec := &DSAPayload{
			msg: []byte(lines[i][5:len(lines[i])]),
			sig: &DSASignature{
				R: mtsn.DecBigInt(lines[i+2][3:len(lines[i+2])]),
				S: mtsn.DecBigInt(lines[i+1][3:len(lines[i+1])]),
			},
			m: mtsn.HexBigInt(lines[i+3][3:len(lines[i+3])]),
		}
		signatures = append(signatures, rec)
	}

	return signatures
}

func FindFirstDuplicateR(payloads []*DSAPayload) (*DSAPayload, *DSAPayload) {
	seen := make(map[string]int)
	for i, payload := range payloads {
		key := fmt.Sprintf("%d", payload.sig.R)
		prev, ok := seen[key]

		if ok {
			return payloads[prev], payload
		}
		seen[key] = i
	}
	panic(fmt.Errorf("Cannot find matching r's"))
}

func CrackSignatureList(dsa *DSA, payloads []*DSAPayload) *big.Int {
	// If two signatures share the same R, it's because they share the same K
	first, second := FindFirstDuplicateR(payloads)

	s := new(big.Int)
	s.Sub(first.sig.S, second.sig.S).Mod(s, dsa.Q)
	sInv := InvModPanic(s, dsa.Q)

	k := new(big.Int)
	k.Sub(first.m, second.m).Mod(k, dsa.Q).Mul(k, sInv).Mod(k, dsa.Q)

	cracker := NewDSACracker(dsa, first.msg, first.sig)

	return cracker.CrackWithLeakedK(k)
}

func Challenge44() {
	signatures := parseChallenge44Signatures()
	dsa := NewDSA()
	privateKey := CrackSignatureList(dsa, signatures)
	fingerprint := Sha1HexRepr(privateKey)

	if fingerprint != "ca8f6f7c66fa362d40760d135b763eb8527d3d52" {
		panic(fmt.Errorf("Got %s as a fingerprint", fingerprint))
	}

	fmt.Printf("Challenge 44: 0x%x\n", privateKey)
}
