package cryptopals

import "encoding/hex"
import "encoding/base64"
import "log"
import "strconv"
import "strings"

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

func CalcRating(msg string) float64 {
	rating := 0.0
	for _, ch := range msg {
		if ch < 32 && ch > 0 {
			rating -= 0.1
		} else {
			lowered_character := []byte(strings.ToLower(string(ch)))[0]
			rating += frequency[lowered_character]
		}
	}
	return rating
}

func SafeXORByte(dst []byte, a []byte, b byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
	return n
}

func SafeXORBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%len(b)]
	}
	return n
}

func msg2bin(msg string) string {
	bin_ := ""
	for _, byte_ := range []byte(msg) {
		converted := strconv.FormatInt(int64(byte_), 2)
		converted = strings.Repeat("0", 8-len(converted)) + converted
		bin_ += converted
	}
	return bin_
}

func DecodeHex(msg string) []byte {
	src := []byte(msg)
	bin := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(bin, src)
	return bin
}

func HammingDistance(message1, message2 string) int {
	bin1 := msg2bin(message1)
	bin2 := msg2bin(message2)
	counts := 0
	for i, ch := range bin1 {
		if byte(ch) != bin2[i] {
			counts += 1
		}
	}
	return counts
}

func HexToBase64(hex_string string) string {
	src := []byte(hex_string)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(dst)
	return encoded
}
