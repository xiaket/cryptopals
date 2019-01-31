package lib

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHexToBase64(test *testing.T) {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	encoded := string(HexToBase64([]byte(hex_string)))
	assert.Equal(test, encoded, expected, "Incorrect base64ed string: %s, want: %s.", encoded, expected)
}

func TestHammingDistance(test *testing.T) {
	const message1 = "this is a test"
	const message2 = "wokka wokka!!!"
	d := HammingDistance([]byte(message1), []byte(message2))
	assert.Equal(test, d, 37, "Incorrect Hamming Distance: %d, want: %d.", d, 37)
}

func TestProb3(test *testing.T) {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	const expected = "Cooking MC's like a pound of bacon"
	unhexed := make([]byte, hex.DecodedLen(len(message)))
	n, _ := hex.Decode(unhexed, []byte(message))
	unhexed_ := unhexed[:n]
	_, guess := DecryptSingleByteXOR([]byte(unhexed_))
	assert.Equal(test, expected, string(guess), "Incorrect guess result: %s, want: %s.", string(guess), expected)
}

func TestPKCS7Padding(test *testing.T) {
	const message = "YELLOW SUBMARINE"
	expected4 := []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4}
	padded := PKCS7Padding([]byte(message), 20)
	for i, ch := range expected4 {
		if ch != padded[i] {
			test.Errorf("Incorrect padded result in %d: %s, want: %s.", i, string(padded[i]), string(ch))
		}
	}
	expected8 := []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 8, 8, 8, 8, 8, 8, 8, 8}
	padded = PKCS7Padding([]byte(message), 24)
	for i, ch := range expected8 {
		if ch != padded[i] {
			test.Errorf("Incorrect padded result in %d: %s, want: %s.", i, string(padded[i]), string(ch))
		}
	}
}
