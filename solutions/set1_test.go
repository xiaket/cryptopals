package solutions

import "bufio"
import "encoding/hex"
import "encoding/base64"
import "fmt"
import "log"
import "os"
import "../lib"
import "testing"

func TestProb1(test *testing.T) {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	encoded := Prob1()
	if encoded != expected {
		test.Errorf("Incorrect base64ed string: %s, want: %s.", encoded, expected)
	}
}

func TestHammingDistance(test *testing.T) {
	const message1 = "this is a test"
	const message2 = "wokka wokka!!!"
	hamming_distance := cryptopals.HammingDistance(message1, message2)
	if hamming_distance != 37 {
		test.Errorf("Incorrect Hamming Distance: %d, want: %d.", hamming_distance, 37)
	}
}
