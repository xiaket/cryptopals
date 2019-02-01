package set2

import (
	"github.com/xiaket/cryptopals/pkg/testutil"
	"testing"
)

func TestProb10(test *testing.T) {
	const key = "YELLOW SUBMARINE"
	const prefix = "I'm back and I'm ringin' the bell"
	const length = 2880
	iv := make([]byte, 16)
	decrypted := prob10([]byte(key), iv)
	testutil.VerifyPrefixAndLength(string(decrypted), prefix, length, test)
}
