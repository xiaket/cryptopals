package cryptopals

import "bytes"
import "testing"

func TestHexToBase64(test *testing.T) {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	encoded := HexToBase64(hex_string)
	if encoded != expected {
		test.Errorf("Incorrect base64ed string: %s, want: %s.", encoded, expected)
	}
}

func TestDecodeHex(test *testing.T) {
	values := map[string][]byte{
		"1c0111001f010100061a024b53535009181c": []byte{28, 1, 17, 0, 31, 1, 1, 0, 6, 26, 2, 75, 83, 83, 80, 9, 24, 28},
		"686974207468652062756c6c277320657965": []byte{104, 105, 116, 32, 116, 104, 101, 32, 98, 117, 108, 108, 39, 115, 32, 101, 121, 101},
	}
	for value := range values {
		decoded := DecodeHex(value)
		if !bytes.Equal(decoded, values[value]) {
			test.Errorf("Incorrect decoded hex: %s, want: %s.", decoded, values[value])
		}
	}
}

func TestHammingDistance(test *testing.T) {
	const message1 = "this is a test"
	const message2 = "wokka wokka!!!"
	hamming_distance := HammingDistance(message1, message2)
	if hamming_distance != 37 {
		test.Errorf("Incorrect Hamming Distance: %d, want: %d.", hamming_distance, 37)
	}
}
