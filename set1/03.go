package main

import "strings"
import "encoding/hex"
import "fmt"

var frequency = map[byte]float64{
	'a': 0.08167,
	'b': 0.01492,
	'e': 0.12702,
	'c': 0.02782,
	'd': 0.04253,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

func main() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	const suspects = "abcdefghijklmnopqrstuvwxyz"
	unhexed, _ := hex.DecodeString(message)

	dst := make([]byte, len(unhexed))
	for _, suspect := range suspects {
		safeXORBytes(dst, unhexed, byte(suspect))
		decoded := string(dst)
		rating := calc_rating(decoded)
		if rating > 1.0 {
			fmt.Println(suspect, dst, rating, decoded)
		}
	}
	// hand picked result: cOOKINGmcSLIKEAPOUNDOFBACON
}

func calc_rating(msg string) float64 {
	rating := 0.0
	for _, ch := range msg {
		lowered_character := []byte(strings.ToLower(string(ch)))[0]
		rating += frequency[lowered_character]
	}
	return rating
}

func safeXORBytes(dst []byte, a []byte, b byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
	return n
}
