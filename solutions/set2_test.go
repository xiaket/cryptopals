package solutions

import "testing"

func TestProb10(test *testing.T) {
	const key = "YELLOW SUBMARINE"
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2880
	iv := make([]byte, 16)
	decrypted := prob10([]byte(key), iv)
	verifyPrefixAndLength(string(decrypted), prefix, length, test)
}
