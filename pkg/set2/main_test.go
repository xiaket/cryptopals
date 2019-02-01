package set2

import (
	"github.com/stretchr/testify/assert"
	"github.com/xiaket/cryptopals/pkg/lib"
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

func TestProb11(test *testing.T) {
	plaintext := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	for i := 0; i < 10; i++ {
		encrypted, mode := lib.EncryptionOracle(plaintext)
		detected := lib.DetectionOracle(encrypted)
		assert.Equal(test, detected, mode)
	}
}
