// Package cryptopals provides functions used in the solution
// of cryptopals problems.
package cryptopals

import "encoding/hex"
import "encoding/base64"
import "os"
import "path/filepath"
import "strconv"
import "strings"

// CalcRating calculate the rating of a string based on letter frequency.
// The higher the rating, the more likely the string is a sentence in English.
func CalcRating(msg string) float64 {
	// Source: http://www.macfreek.nl/memory/Letter_Distribution
	var frequency = map[byte]float64{
		'a': 0.08023,
		'b': 0.01556,
		'c': 0.02773,
		'd': 0.04104,
		'e': 0.12510,
		'f': 0.02414,
		'g': 0.02003,
		'h': 0.05953,
		'i': 0.07021,
		'j': 0.00140,
		'k': 0.00697,
		'l': 0.04109,
		'm': 0.02470,
		'n': 0.06983,
		'o': 0.07592,
		'p': 0.01840,
		'q': 0.00108,
		'r': 0.06087,
		's': 0.06521,
		't': 0.09195,
		'u': 0.02810,
		'v': 0.00965,
		'w': 0.02069,
		'x': 0.00183,
		'y': 0.01800,
		'z': 0.00073,
		' ': 0.22426, // 18.317 / 10.218 * 12.510
	}
	rating := 0.0
	for _, ch := range msg {
		switch {
		case ch < 32:
			// Bad characters, a big minus.
			rating += -0.3
		case (ch >= 33 && ch < 47) || (ch >= 58 && ch < 65) || (ch >= 91 && ch < 96):
			// symbols, a little minus.
			rating += -0.05
		case ch >= 48 && ch < 57:
			// digits, a little plus.
			rating += 0.05
		default:
			lowered_character := []byte(strings.ToLower(string(ch)))[0]
			rating += frequency[lowered_character]
		}
	}
	return rating
}

// XORByte uses a single byte(b) to run a xor operation on all the bytes in a
func XORByte(dst []byte, a []byte, b byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
	return n
}

// XORByte uses an array of bytes(b) to run a xor operation on all the bytes in a
func XORBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%len(b)]
	}
	return n
}

// msg2bin converts a message in string to another string, where all of
func msg2bin(msg string) string {
	bin_ := ""
	for _, byte_ := range []byte(msg) {
		converted := strconv.FormatInt(int64(byte_), 2)
		converted = strings.Repeat("0", 8-len(converted)) + converted
		bin_ += converted
	}
	return bin_
}

// GitRootDir will find the root directory of this repo.
func GitRootDir() (bool, string) {
	dir, _ := filepath.Abs(".")
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "/.git")); err == nil {
			return true, dir
		}
		dir = filepath.Dir(dir)
	}
	return false, ""
}

// DecodeHex is a thin wrapper around hex.Decode to accept a string as input.
func DecodeHex(msg string) []byte {
	src := []byte(msg)
	bin := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(bin, src)
	return bin
}

// HammingDistance calculate the Hamming Distance of two strings.
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

// HexToBase64 encode a string in hex using base64.
func HexToBase64(hex_string string) string {
	bin := DecodeHex(hex_string)
	encoded := base64.StdEncoding.EncodeToString(bin)
	return encoded
}
